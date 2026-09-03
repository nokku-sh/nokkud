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

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// TestRecoverAndLog verifies a panic in a handler goroutine is contained and
// does not escape into the server, and that cleanup still runs.
func TestRecoverAndLog(t *testing.T) {
	buf := &syncedBuffer{}
	s := &Server{logger: slog.New(slog.NewTextHandler(buf, nil))}

	// Trigger a panic so recoverAndLog both contains it and runs cleanup.
	cleanupRan := false
	func() {
		defer s.recoverAndLog("test", func() { cleanupRan = true })
		panic("handler panic must be contained")
	}()

	if !cleanupRan {
		t.Fatal("cleanup did not run after recovered panic")
	}
	if got := buf.String(); !strings.Contains(got, "handler panic must be contained") {
		t.Fatalf("panic not logged, got: %s", got)
	}
	if got := buf.String(); !strings.Contains(got, "recovered panic") {
		t.Fatalf("recovery not logged, got: %s", got)
	}
}

// TestServerDisconnectReapsCommand verifies that when the client disconnects
// mid-command, the running process is killed and the session winds down
// instead of hanging.
func TestServerDisconnectReapsCommand(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	if err = sess.Start("sleep 30"); err != nil {
		t.Fatalf("start: %v", err)
	}

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
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	if err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err = sess.Start("sleep 30"); err != nil {
		t.Fatalf("start: %v", err)
	}

	// The signal is forwarded to the running command's process.
	if err = sess.Signal(ssh.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- sess.Wait()
	}()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("expected non-zero exit after signal")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("process did not terminate after signal")
	}
}

// TestServerWindowChange verifies pty resize requests reach the running
// process.
func TestServerWindowChange(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	if err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	// stty size prints "rows cols". Window change must land before exec.
	if err = sess.WindowChange(40, 20); err != nil {
		t.Fatalf("window change: %v", err)
	}
	out, err := sess.Output("stty size")
	if err != nil {
		t.Fatalf("exec stty: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "40 20" {
		t.Fatalf("stty size = %q, want %q", got, "40 20")
	}
}

// TestServerEnvWhitelist verifies only whitelisted client environment
// variables reach the session. Shell/loader-affecting variables are dropped.
func TestServerEnvWhitelist(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	_ = sess.Setenv("LANG", "de_DE.UTF-8")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")
	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LD_PRELOAD", "/tmp/lib.so")
	_ = sess.Setenv("SSH_AUTH_SOCK", "/tmp/evil.sock")

	out, err := sess.Output(
		`printf '%s|%s|%s|%s|%s' "$LANG" "$LC_MESSAGES" "$BASH_ENV" "$LD_PRELOAD" "$SSH_AUTH_SOCK"`,
	)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	fields := strings.Split(string(out), "|")
	if len(fields) != 5 {
		t.Fatalf("env output = %q", out)
	}
	// LANG and LC_MESSAGES pass through. BASH_ENV and LD_PRELOAD are refused.
	if fields[0] != "de_DE.UTF-8" || fields[1] != "fr_FR.UTF-8" {
		t.Fatalf("whitelisted env = %q, %q; want de_DE.UTF-8, fr_FR.UTF-8", fields[0], fields[1])
	}
	if fields[2] != "" || fields[3] != "" {
		t.Fatalf("loader-affecting env leaked: BASH_ENV=%q LD_PRELOAD=%q", fields[2], fields[3])
	}
	// SSH_AUTH_SOCK must not be the client-injected value (it may inherit the
	// daemon's own agent socket).
	if fields[4] == "/tmp/evil.sock" {
		t.Fatalf("client-injected SSH_AUTH_SOCK reached the session")
	}
}

// TestServerForceCommandBlocksEnv verifies a certificate force-command runs
// with the server-provided environment only. Client-supplied variables (even
// whitelisted ones) are refused so an injected BASH_ENV cannot override a
// restricted command.
func TestServerForceCommandBlocksEnv(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	cert := func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": `printf 'force:%s' "$BASH_ENV"`}
	}
	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, cert, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	_ = sess.Setenv("BASH_ENV", "boom")
	_ = sess.Setenv("LC_MESSAGES", "fr_FR.UTF-8")

	// The requested command is ignored. The certificate's force-command runs
	// instead, and sees neither variable.
	out, err := sess.Output("echo this-should-be-ignored")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "force:" {
		t.Fatalf("output = %q, want %q", out, "force:")
	}
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
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)
	if err := paths.Verify(); err != nil {
		t.Fatalf("verify paths: %v", err)
	}

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
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.SetRecordingSinkFactory(factory)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() { _ = srv.Serve(l) }()

	client, err := dial(t, l.Addr().String(), cur, userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("printf hello-recorded")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "hello-recorded" {
		t.Fatalf("output = %q, want %q", out, "hello-recorded")
	}

	// finish() closes the recorder before the exit status is sent, so the
	// sink is complete by the time Output returns.
	select {
	case <-sink.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("recording sink was never closed")
	}

	gr, err := gzip.NewReader(&sink.data)
	if err != nil {
		t.Fatalf("sink data is not gzip: %v", err)
	}
	cast, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	if !strings.Contains(string(cast), `"o"`) {
		t.Fatalf("recording has no output event, got: %s", cast)
	}
	if !strings.Contains(string(cast), "hello-recorded") {
		t.Fatalf("recorded output missing command output, got: %s", cast)
	}
}
