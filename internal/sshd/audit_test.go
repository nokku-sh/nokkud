package sshd

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// TestServerAuditEvents verifies auth success/failure, session, and command
// events are emitted to the audit sink.
func TestServerAuditEvents(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	sink, err := audit.New(dir)
	must.NoError(err)
	addr, closeFn := startTestServerOpts(t, ca, Options{Audit: sink})
	defer closeFn()

	// A successful login + command.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("echo hi")
	must.NoError(err)
	is.Equal("hi\n", string(out))
	_ = sess.Close()
	_ = client.Close()

	// A failed login (wrong principal).
	_, err = dial(t, addr, currentUser(t), userCert(t, ca, "some-other-principal"))
	must.Error(err, "login with wrong principal unexpectedly succeeded")

	must.NoError(sink.Close())
	types := readEventTypes(t, dir)
	for _, want := range []audit.EventType{
		audit.EventAuthSuccess,
		audit.EventAuthFailure,
		audit.EventSessionStart,
		audit.EventSessionEnd,
		audit.EventCommand,
	} {
		is.True(slices.Contains(types, want), "missing audit event %q in %v", want, types)
	}
}

func readEventTypes(t *testing.T, dir string) []audit.EventType {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	require.NoError(t, err)
	var types []audit.EventType
	for _, path := range matches {
		f, openErr := os.Open(path)
		require.NoError(t, openErr)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var ev audit.Event
			require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
			types = append(types, ev.Type)
		}
		_ = f.Close()
	}
	return types
}

// wrongKeySigner presents a valid certificate but signs with another key, like
// a client that copied someone's public cert without the private key.
type wrongKeySigner struct {
	cert  ssh.PublicKey
	other ssh.Signer
}

func (w wrongKeySigner) PublicKey() ssh.PublicKey { return w.cert }

func (w wrongKeySigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return w.other.Sign(r, data)
}

func TestServerAuditNoSuccessWithoutKey(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	sink, err := audit.New(dir)
	must.NoError(err)
	addr, closeFn := startTestServerOpts(t, ca, Options{Audit: sink})
	defer closeFn()

	newSigner := func() (ssh.PublicKey, ssh.Signer) {
		_, priv, keyErr := ed25519.GenerateKey(rand.Reader)
		must.NoError(keyErr)
		signer, keyErr := ssh.NewSignerFromKey(priv)
		must.NoError(keyErr)
		return signer.PublicKey(), signer
	}
	pub, _ := newSigner()
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{testPrincipal},
		ValidBefore:     ssh.CertTimeInfinity,
		Extensions:      maps.Clone(defaultExtensions),
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer))
	_, other := newSigner()

	_, err = dial(t, addr, currentUser(t), ssh.PublicKeys(wrongKeySigner{cert: cert, other: other}))
	must.Error(err, "login without the private key unexpectedly succeeded")

	must.NoError(sink.Close())
	assert.NotContains(t, readEventTypes(t, dir), audit.EventAuthSuccess)
}

// TestServerAuditFileTransferAndRemoteForward verifies SFTP (which scp uses)
// and -R forwards land on the audit trail.
func TestServerAuditFileTransferAndRemoteForward(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	sink, err := audit.New(dir)
	must.NoError(err)
	addr, closeFn := startTestServerOpts(t, ca, Options{Audit: sink, Policy: DefaultPolicy})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	must.NoError(err)
	_, err = sc.Getwd()
	must.NoError(err)
	_ = sc.Close()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)
	_ = ln.Close()

	_ = client.Close()
	closeFn()
	must.NoError(sink.Close())
	types := readEventTypes(t, dir)
	assert.Contains(t, types, audit.EventSubsystem)
	assert.Contains(t, types, audit.EventRemoteForward)
}
