package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os/user"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/state"
)

const testPrincipal = "9a3c2a0f-5f1e-4a7b-9c4d-2e6b8f0a1c3d"

type testCA struct {
	pub    ssh.PublicKey
	signer ssh.Signer
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("CA public key: %v", err)
	}
	return testCA{pub: pub, signer: signer}
}

// userCert builds a client auth method presenting a user certificate signed
// by ca, valid for the given principals.
func userCert(t *testing.T, ca testCA, principals ...string) ssh.AuthMethod {
	t.Helper()
	return userCertOpts(t, ca, nil, principals...)
}

// userCertOpts is userCert with certificate options applied before signing
// (critical options or extensions).
func userCertOpts(
	t *testing.T,
	ca testCA,
	opts func(*ssh.Certificate),
	principals ...string,
) ssh.AuthMethod {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("user signer: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("user public key: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-user",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if opts != nil {
		opts(cert)
	}
	if err = cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return ssh.PublicKeys(certSigner)
}

// startTestServer boots a server on an ephemeral port trusting ca. The
// default principals allow testPrincipal for the current user only.
func startTestServer(t *testing.T, ca testCA) (addr string, closeFn func()) {
	t.Helper()
	return startTestServerOpts(t, ca, Options{})
}

// startTestServerOpts is startTestServer with extra Options applied.
func startTestServerOpts(t *testing.T, ca testCA, extra Options) (addr string, closeFn func()) {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	principals := func(username string) []string {
		if username == cur.Username {
			return []string{testPrincipal}
		}
		return nil
	}

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	extra.Principals = principals
	extra.TrustedCAs = []ssh.PublicKey{ca.pub}
	srv, err := New(extra)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String(), func() { _ = l.Close() }
}

func dial(t *testing.T, addr, username string, auth ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

func TestServerExec(t *testing.T) {
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

	out, err := sess.Output("printf hello-nokkud")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "hello-nokkud" {
		t.Fatalf("output = %q, want %q", out, "hello-nokkud")
	}
}

func TestServerExecExitStatus(t *testing.T) {
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

	if err = sess.Run("exit 7"); err != nil {
		var ee *ssh.ExitError
		if !errors.As(err, &ee) || ee.ExitStatus() != 7 {
			t.Fatalf("expected exit status 7, got %v", err)
		}
	}
}

func TestServerExecExitSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX signals on windows")
	}

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

	// The command kills its own shell, so the server must report exit-signal
	// (RFC 4254) instead of exit-status, like OpenSSH. The Go client maps
	// that to the conventional 128+signal exit status.
	err = sess.Run("kill -TERM $$")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if ee.Signal() != "TERM" {
		t.Fatalf("signal = %q, want TERM", ee.Signal())
	}
	if ee.ExitStatus() != 143 {
		t.Fatalf("exit status = %d, want 143 (128+SIGTERM)", ee.ExitStatus())
	}
}

func TestServerPTYExec(t *testing.T) {
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

	if err = sess.RequestPty("xterm-256color", 80, 24, ssh.TerminalModes{}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	out, err := sess.Output("printf pty-ok")
	if err != nil {
		t.Fatalf("pty exec: %v", err)
	}
	if string(out) != "pty-ok" {
		t.Fatalf("pty output = %q, want %q", out, "pty-ok")
	}
}

func TestServerDeniesUntrustedCA(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	other := newTestCA(t)
	if _, err := dial(t, addr, currentUser(t), userCert(t, other, testPrincipal)); err == nil {
		t.Fatal("expected auth to fail with untrusted CA")
	}
}

func TestServerDeniesWrongPrincipal(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	if _, err := dial(t, addr, currentUser(t), userCert(t, ca, "unknown-principal")); err == nil {
		t.Fatal("expected auth to fail with unauthorized principal")
	}
}

func TestServerDeniesNoRules(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	// No principals rules exist for this (likely nonexistent) username.
	if _, err := dial(t, addr, "nobody-nokku-test", userCert(t, ca, testPrincipal)); err == nil {
		t.Fatal("expected auth to fail with no access rules")
	}
}

func TestServerDeniesPlainKey(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, err = dial(t, addr, currentUser(t), ssh.PublicKeys(signer)); err == nil {
		t.Fatal("expected auth to reject a non-certificate key")
	}
}

func currentUser(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return cur.Username
}

// TestHostKeysStable verifies that a generated host key survives reloads: if
// it changed, every known_hosts entry would break on daemon restart.
func TestHostKeysStable(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	s1, c1, err := loadHostKeys()
	if err != nil {
		t.Fatalf("load host keys: %v", err)
	}
	for _, c := range c1 {
		defer func() { _ = c.Close() }()
	}
	if len(s1) == 0 {
		t.Fatal("expected at least one host key")
	}
	first := s1[0].PublicKey().Marshal()

	s2, c2, err := loadHostKeys()
	if err != nil {
		t.Fatalf("reload host keys: %v", err)
	}
	for _, c := range c2 {
		defer func() { _ = c.Close() }()
	}
	second := s2[0].PublicKey().Marshal()
	if !bytes.Equal(first, second) {
		t.Fatal("host key changed across reloads")
	}
}

// TestNewWithoutTrustedCA verifies the server starts with no trusted CA on
// first boot (the CA file lands after the first certificate sync). Reload
// picks it up. Without CAs, no login can succeed until then.
func TestNewWithoutTrustedCA(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(string) []string {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("expected server to start without a trusted CA, got: %v", err)
	}
	if len(srv.trustedCAs) != 0 {
		t.Fatalf("expected zero trusted CAs, got %d", len(srv.trustedCAs))
	}
}

// TestServerLivePrincipals verifies that adding a principal to the shared
// cache takes effect on the next connection, without restarting the server.
func TestServerLivePrincipals(t *testing.T) {
	ca := newTestCA(t)
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	cache := state.NewCache()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(username string) []string {
			return cache.GetUUIDs(username)
		},
		TrustedCAs: []ssh.PublicKey{ca.pub},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	defer l.Close()

	// No rules yet: denied.
	if _, err = dial(
		t,
		l.Addr().String(),
		cur.Username,
		userCert(t, ca, testPrincipal),
	); err == nil {
		t.Fatal("expected auth to fail before the principal is granted")
	}

	// Backend push lands in the shared cache: now allowed.
	cache.Replace(map[string][]string{cur.Username: {testPrincipal}}, nil, 0)
	client, err := dial(t, l.Addr().String(), cur.Username, userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial after cache update: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if _, err = sess.Output("printf live"); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
