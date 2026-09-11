package sshd

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// TestRecoverAndLog verifies a panic in a handler goroutine is contained and
// does not escape into the server, and that cleanup still runs.
func TestRecoverAndLog(t *testing.T) {
	is := assert.New(t)
	buf := &syncedBuffer{}
	s := &Server{logger: slog.New(slog.NewTextHandler(buf, nil))}

	// Trigger a panic so recoverAndLog both contains it and runs cleanup.
	cleanupRan := false
	func() {
		defer s.recoverAndLog("test", func() { cleanupRan = true })
		panic("handler panic must be contained")
	}()

	is.True(cleanupRan, "cleanup did not run after recovered panic")
	is.Contains(buf.String(), "handler panic must be contained")
	is.Contains(buf.String(), "recovered panic")
}

// TestServerDisconnectReapsCommand verifies that when the client disconnects
// mid-command, the running process is killed and the session winds down
// instead of hanging.
func TestServerDisconnectReapsCommand(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.Start("sleep 30"), "start")

	// Drop the connection while the command is running. The server must
	// kill the child and return promptly.
	done := make(chan struct{})
	go func() {
		_ = client.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client close hung; server likely failed to reap the command")
	}
}

// TestServerSignalForwards verifies a client signal reaches the running
// process and terminates it with the expected status.
func TestServerSignalForwards(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")
	must.NoError(sess.Start("sleep 30"), "start")

	// The signal is forwarded to the running command's process.
	must.NoError(sess.Signal(ssh.SIGTERM), "signal")

	done := make(chan error, 1)
	go func() {
		done <- sess.Wait()
	}()
	select {
	case err = <-done:
		must.Error(err, "expected non-zero exit after signal")
	case <-time.After(5 * time.Second):
		t.Fatal("process did not terminate after signal")
	}
}

// TestServerWindowChange verifies pty resize requests reach the running
// process.
func TestServerWindowChange(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	must.NoError(sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}), "request pty")

	// stty size prints "rows cols". Window change must land before exec.
	must.NoError(sess.WindowChange(40, 20), "window change")
	out, err := sess.Output("stty size")
	must.NoError(err, "exec stty")
	is.Equal("40 20", strings.TrimSpace(string(out)))
}

// TestServerEnvWhitelist verifies only whitelisted client environment
// variables reach the session. Shell/loader-affecting variables are dropped.
func TestServerEnvWhitelist(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	_ = sess.Setenv("LANG", "de_DE.UTF-8")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")
	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LD_PRELOAD", "/tmp/lib.so")
	_ = sess.Setenv("SSH_AUTH_SOCK", "/tmp/evil.sock")

	out, err := sess.Output(
		`printf '%s|%s|%s|%s|%s' "$LANG" "$LC_MESSAGES" "$BASH_ENV" "$LD_PRELOAD" "$SSH_AUTH_SOCK"`,
	)
	must.NoError(err, "exec")
	fields := strings.Split(string(out), "|")
	must.Len(fields, 5, "env output = %q", out)
	// LANG and LC_MESSAGES pass through. BASH_ENV and LD_PRELOAD are refused.
	is.Equal("de_DE.UTF-8", fields[0])
	is.Equal("fr_FR.UTF-8", fields[1])
	is.Empty(fields[2])
	is.Empty(fields[3])
	// SSH_AUTH_SOCK must not be the client-injected value (it may inherit the
	// daemon's own agent socket).
	is.NotEqual("/tmp/evil.sock", fields[4])
}

// TestServerForceCommandBlocksEnv verifies a certificate force-command runs
// with the server-provided environment only. Client-supplied variables (even
// whitelisted ones) are refused so an injected BASH_ENV cannot override a
// restricted command.
func TestServerForceCommandBlocksEnv(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	cert := func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": `printf 'force:%s' "$BASH_ENV"`}
	}
	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, cert, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")

	// The requested command is ignored. The certificate's force-command runs
	// instead, and sees neither variable.
	out, err := sess.Output("echo this-should-be-ignored")
	must.NoError(err, "exec")
	is.Equal("force:", string(out))
}

// syncedBuffer appends into a shared string under a mutex, for asserting on
// slog output.
type syncedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// captureSink collects recorder sink writes and signals Close, so tests can
// assert what the daemon would have uploaded.
type captureSink struct {
	mu      sync.Mutex
	data    bytes.Buffer
	closed  chan struct{}
	closeDo sync.Once
}

func (s *captureSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Write(p)
}

func (s *captureSink) Close() error {
	s.closeDo.Do(func() { close(s.closed) })
	return nil
}

// TestPlainSessionRecorded verifies a non-pty exec session is recorded and
// streamed to the sink, so commands that bypass a terminal are still
// captured.
func TestPlainSessionRecorded(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)
	must.NoError(paths.Verify(), "verify paths")

	sink := &captureSink{closed: make(chan struct{})}
	factory := func(context.Context, string, string) io.WriteCloser { return sink }

	cur := currentUser(t)
	ca := newTestCA(t)
	principals := func(username string) []string {
		if username == cur {
			return []string{testPrincipal}
		}
		return nil
	}
	srv, err := New(Options{
		Principals: principals,
		TrustedCAs: []ssh.PublicKey{ca.pub},
		Tunables:   Tunables{Record: true},
	})
	must.NoError(err, "new server")
	srv.SetRecordingSinkFactory(factory)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	defer func() { _ = l.Close() }()
	go func() { _ = srv.Serve(l) }()

	client, err := dial(t, l.Addr().String(), cur, userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	must.NoError(err, "stdin pipe")
	stdout, err := sess.StdoutPipe()
	must.NoError(err, "stdout pipe")

	must.NoError(sess.Start("cat"), "start")
	_, err = io.WriteString(stdin, "piped-input\n")
	must.NoError(err)
	must.NoError(stdin.Close())

	out, err := io.ReadAll(stdout)
	must.NoError(err, "read stdout")
	must.NoError(sess.Wait(), "wait")
	is.Equal("piped-input\n", string(out))

	// finish() closes the recorder before the exit status is sent, so the
	// sink is complete by the time Wait returns.
	select {
	case <-sink.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("recording sink was never closed")
	}

	gr, err := gzip.NewReader(&sink.data)
	must.NoError(err, "sink data is not gzip")
	cast, err := io.ReadAll(gr)
	must.NoError(err, "read recording")
	is.Contains(string(cast), `"o"`, "plain sessions must still record output")
	is.NotContains(string(cast), `"i"`, "plain sessions must not record stdin")
}

// TestSessionDeniedByNologin verifies /etc/nologin is honoured at session
// start. Authentication still succeeds (it is certificate based); the
// session channel is closed instead.
func TestSessionDeniedByNologin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, where /etc/nologin does not apply")
	}
	is := assert.New(t)
	must := require.New(t)

	nologin := filepath.Join(t.TempDir(), "nologin")
	must.NoError(os.WriteFile(nologin, []byte("maintenance\n"), 0o644))

	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{NologinFile: nologin})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	if err == nil {
		err = sess.Run("true")
		_ = sess.Close()
	}
	is.Error(err, "session started while /etc/nologin was present")
}

// TestRecordingCorrelatesWebSessionID verifies the env NOKKU_SESSION_ID is
// honoured only for certificates the control plane minted for a web terminal
// session. A direct login must not be able to label its recording with
// another session's id, so it falls back to the daemon-generated one.
func TestRecordingCorrelatesWebSessionID(t *testing.T) {
	const webSessionID = "0197a3f2-7c1b-7de1-9a2b-3f4c5d6e7f80"

	cases := []struct {
		name         string
		keyID        string
		wantPromoted bool
	}{
		{"web session", "nokku:web:session:" + webSessionID, true},
		{"direct login", "nokku:login:user:" + testPrincipal, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := assert.New(t)
			must := require.New(t)
			t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
			must.NoError(paths.Verify(), "verify paths")

			var mu sync.Mutex
			var gotID string
			sink := &captureSink{closed: make(chan struct{})}
			factory := func(_ context.Context, sessionID, _ string) io.WriteCloser {
				mu.Lock()
				gotID = sessionID
				mu.Unlock()
				return sink
			}

			cur := currentUser(t)
			ca := newTestCA(t)
			principals := func(username string) []string {
				if username == cur {
					return []string{testPrincipal}
				}
				return nil
			}
			srv, err := New(Options{
				Principals: principals,
				TrustedCAs: []ssh.PublicKey{ca.pub},
				Tunables:   Tunables{Record: true},
			})
			must.NoError(err, "new server")
			srv.SetRecordingSinkFactory(factory)
			l, err := net.Listen("tcp", "127.0.0.1:0")
			must.NoError(err, "listen")
			defer func() { _ = l.Close() }()
			go func() { _ = srv.Serve(l) }()

			auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
				c.KeyId = tc.keyID
			}, testPrincipal)
			client, err := dial(t, l.Addr().String(), cur, auth)
			must.NoError(err, "dial")
			defer client.Close()

			sess, err := client.NewSession()
			must.NoError(err, "new session")
			defer sess.Close()

			ok, err := sess.SendRequest("env", true, ssh.Marshal(
				struct{ Name, Value string }{"NOKKU_SESSION_ID", webSessionID},
			))
			must.NoError(err, "env request")
			is.Equal(tc.wantPromoted, ok, "env request accepted")

			_, err = sess.Output("printf env-recorded")
			must.NoError(err, "exec")

			select {
			case <-sink.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("recording sink was never closed")
			}

			mu.Lock()
			defer mu.Unlock()
			if tc.wantPromoted {
				is.Equal(webSessionID, gotID, "recording must carry the env session id")
			} else {
				is.NotEmpty(gotID, "recording must carry a session id")
				is.NotEqual(webSessionID, gotID,
					"a direct login must not hijack another session's recording id")
			}
		})
	}
}
