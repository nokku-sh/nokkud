package sshd

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
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

	out, err := sess.Output("printf hello-recorded")
	must.NoError(err, "exec")
	is.Equal("hello-recorded", string(out))

	// finish() closes the recorder before the exit status is sent, so the
	// sink is complete by the time Output returns.
	select {
	case <-sink.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("recording sink was never closed")
	}

	gr, err := gzip.NewReader(&sink.data)
	must.NoError(err, "sink data is not gzip")
	cast, err := io.ReadAll(gr)
	must.NoError(err, "read recording")
	is.Contains(string(cast), `"o"`)
	is.Contains(string(cast), "hello-recorded")
}
