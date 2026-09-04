package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"maps"
	"net"
	"os/user"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "generate CA")
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "CA signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err, "CA public key")
	return testCA{pub: pub, signer: signer}
}

// userCert builds a client auth method presenting a user certificate signed
// by ca, valid for the given principals.
func userCert(t *testing.T, ca testCA, principals ...string) ssh.AuthMethod {
	t.Helper()
	return userCertOpts(t, ca, nil, principals...)
}

// defaultExtensions mirrors the backend's default cert template. The daemon
// enforces permit-* semantics, so tests need them granted explicitly.
var defaultExtensions = map[string]string{
	"permit-pty":              "",
	"permit-user-rc":          "",
	"permit-port-forwarding":  "",
	"permit-agent-forwarding": "",
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
	require.NoError(t, err, "generate user key")
	userSigner, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "user signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	require.NoError(t, err, "user public key")
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-user",
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
		Extensions:      maps.Clone(defaultExtensions),
	}
	if opts != nil {
		opts(cert)
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca.signer), "sign cert")
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	require.NoError(t, err, "cert signer")
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
	require.NoError(t, err, "current user")
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
	require.NoError(t, err, "new server")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen")
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

	out, err := sess.Output("printf hello-nokkud")
	must.NoError(err, "exec")
	is.Equal("hello-nokkud", string(out))
}

func TestServerExecExitStatus(t *testing.T) {
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

	err = sess.Run("exit 7")
	var ee *ssh.ExitError
	must.ErrorAs(err, &ee)
	is.Equal(7, ee.ExitStatus())
}

func TestServerExecExitSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX signals on windows")
	}

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

	// The command kills its own shell, so the server must report exit-signal
	// (RFC 4254) instead of exit-status, like OpenSSH. The Go client maps
	// that to the conventional 128+signal exit status.
	err = sess.Run("kill -TERM $$")
	var ee *ssh.ExitError
	must.ErrorAs(err, &ee)
	is.Equal("TERM", ee.Signal())
	is.Equal(143, ee.ExitStatus())
}

func TestServerPTYExec(t *testing.T) {
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

	must.NoError(sess.RequestPty("xterm-256color", 80, 24, ssh.TerminalModes{}), "request pty")
	out, err := sess.Output("printf pty-ok")
	must.NoError(err, "pty exec")
	is.Equal("pty-ok", string(out))
}

func TestServerDeniesUntrustedCA(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	other := newTestCA(t)
	_, err := dial(t, addr, currentUser(t), userCert(t, other, testPrincipal))
	is.Error(err, "expected auth to fail with untrusted CA")
}

func TestServerDeniesWrongPrincipal(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, err := dial(t, addr, currentUser(t), userCert(t, ca, "unknown-principal"))
	is.Error(err, "expected auth to fail with unauthorized principal")
}

func TestServerDeniesNoRules(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	// No principals rules exist for this (likely nonexistent) username.
	_, err := dial(t, addr, "nobody-nokku-test", userCert(t, ca, testPrincipal))
	is.Error(err, "expected auth to fail with no access rules")
}

func TestServerDeniesPlainKey(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate key")
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err, "signer")
	_, err = dial(t, addr, currentUser(t), ssh.PublicKeys(signer))
	is.Error(err, "expected auth to reject a non-certificate key")
}

func currentUser(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	require.NoError(t, err, "current user")
	return cur.Username
}

// TestHostKeysStable verifies that a generated host key survives reloads: if
// it changed, every known_hosts entry would break on daemon restart.
func TestHostKeysStable(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	s1, c1, err := loadHostKeys()
	must.NoError(err, "load host keys")
	for _, c := range c1 {
		defer func() { _ = c.Close() }()
	}
	is.NotEmpty(s1, "expected at least one host key")
	first := s1[0].PublicKey().Marshal()

	s2, c2, err := loadHostKeys()
	must.NoError(err, "reload host keys")
	for _, c := range c2 {
		defer func() { _ = c.Close() }()
	}
	second := s2[0].PublicKey().Marshal()
	is.Equal(first, second)
}

// TestNewWithoutTrustedCA verifies the server starts with no trusted CA on
// first boot (the CA file lands after the first certificate sync). Reload
// picks it up. Without CAs, no login can succeed until then.
func TestNewWithoutTrustedCA(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(string) []string {
			return nil
		},
	})
	must.NoError(err, "expected server to start without a trusted CA")
	is.Empty(srv.trustedCAs)
}

// TestServerLivePrincipals verifies that adding a principal to the shared
// cache takes effect on the next connection, without restarting the server.
func TestServerLivePrincipals(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	cur, err := user.Current()
	require.NoError(t, err, "current user")

	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	cache := state.NewCache()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(username string) []string {
			return cache.GetUUIDs(username)
		},
		TrustedCAs: []ssh.PublicKey{ca.pub},
	})
	must.NoError(err, "new server")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	go func() { _ = srv.Serve(l) }()
	defer l.Close()

	// No rules yet: denied.
	_, err = dial(t, l.Addr().String(), cur.Username, userCert(t, ca, testPrincipal))
	must.Error(err, "expected auth to fail before the principal is granted")

	// Backend push lands in the shared cache: now allowed.
	cache.Replace(map[string][]string{cur.Username: {testPrincipal}}, nil, 0)
	client, err := dial(t, l.Addr().String(), cur.Username, userCert(t, ca, testPrincipal))
	must.NoError(err, "dial after cache update")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err, "new session")
	defer sess.Close()
	_, err = sess.Output("printf live")
	must.NoError(err, "exec")
}
