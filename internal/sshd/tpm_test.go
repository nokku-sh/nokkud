package sshd

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

// withSimulatedTPM points the host key loader at the TPM simulator and
// restores the real loader afterwards.
func withSimulatedTPM(t *testing.T) transport.TPMCloser {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("tpm simulator unavailable: %v", err)
	}
	old := openHostKeyTPM
	openHostKeyTPM = func(salt []byte) (*tpm.Key, error) { return tpm.NewKey(sim, salt) }
	t.Cleanup(func() {
		openHostKeyTPM = old
		_ = sim.Close()
	})
	return sim
}

// TestTPMHostKey verifies the TPM-backed host identity: only the public key
// lands on disk, no private key file exists, and the identity is stable
// across reloads (deterministic TPM derivation).
func TestTPMHostKey(t *testing.T) {
	withSimulatedTPM(t)
	p := paths.Paths{ConfigDir: t.TempDir()}

	keys, closers, err := loadHostKeys(p)
	if err != nil {
		t.Fatalf("load host keys: %v", err)
	}
	for _, c := range closers {
		defer func() { _ = c.Close() }()
	}
	if len(keys) != 1 {
		t.Fatalf("expected one host key, got %d", len(keys))
	}
	first := keys[0].PublicKey().Marshal()

	// Public half must be on disk for the certificate manager...
	pubData, err := os.ReadFile(p.TPMHostKeyPub())
	if err != nil {
		t.Fatalf("tpm host public key not written: %v", err)
	}
	// ...and no private key file may exist.
	if _, err = os.Stat(p.SoftwareHostKey()); !os.IsNotExist(err) {
		t.Fatalf("TPM host key must not leave a private key on disk, found %s", p.SoftwareHostKey())
	}

	// The parsed pub file must match the served key.
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		t.Fatalf("parse written pub: %v", err)
	}
	if !bytes.Equal(pub.Marshal(), first) {
		t.Fatal("written public key does not match the served key")
	}

	// Deterministic: reloading yields the same identity (no known_hosts
	// breakage on daemon restart).
	keys2, closers2, err := loadHostKeys(p)
	if err != nil {
		t.Fatalf("reload host keys: %v", err)
	}
	for _, c := range closers2 {
		defer func() { _ = c.Close() }()
	}
	if !bytes.Equal(keys2[0].PublicKey().Marshal(), first) {
		t.Fatal("TPM host key changed across reloads")
	}
}

// TestTPMHostKeyRemovesSoftwareKey verifies that migrating a machine with an
// existing software host key to the TPM identity removes the old key files,
// so the certificate manager and the server present a single identity.
func TestTPMHostKeyRemovesSoftwareKey(t *testing.T) {
	withSimulatedTPM(t)
	configDir := t.TempDir()
	p := paths.Paths{ConfigDir: configDir}

	// A pre-existing software host key, as a pre-TPM install would have.
	software, err := generateHostKey(p)
	if err != nil {
		t.Fatalf("generate software key: %v", err)
	}
	privPath := p.SoftwareHostKey()
	if _, err = os.Stat(privPath); err != nil {
		t.Fatalf("software key not written: %v", err)
	}

	keys, closers, err := loadHostKeys(p)
	if err != nil {
		t.Fatalf("load host keys: %v", err)
	}
	for _, c := range closers {
		defer func() { _ = c.Close() }()
	}

	// The software key files must be gone; the TPM key is the only identity.
	if _, err = os.Stat(privPath); !os.IsNotExist(err) {
		t.Fatal("software host key must be removed after TPM migration")
	}
	if _, err = os.Stat(p.SoftwareHostKeyPub()); !os.IsNotExist(err) {
		t.Fatal("software host public key must be removed after TPM migration")
	}
	if len(keys) != 1 {
		t.Fatalf("expected a single TPM host key, got %d", len(keys))
	}
	if bytes.Equal(software.PublicKey().Marshal(), keys[0].PublicKey().Marshal()) {
		t.Fatal("host identity must change when migrating to the TPM")
	}
}

// TestTPMHostKeyAdoptsCert verifies a host certificate issued for the TPM
// key is presented alongside it after a reload, and that a certificate for
// a stale key (TPM cleared) is dropped instead of served.
func TestTPMHostKeyAdoptsCert(t *testing.T) {
	sim := withSimulatedTPM(t)
	p := paths.Paths{ConfigDir: t.TempDir()}

	ca := newTestCA(t)

	load := func() ssh.Signer {
		t.Helper()
		keys, closers, err := loadHostKeys(p)
		if err != nil {
			t.Fatalf("load host keys: %v", err)
		}
		t.Cleanup(func() {
			for _, c := range closers {
				_ = c.Close()
			}
		})
		return keys[0]
	}

	// First boot: plain key, no certificate.
	plain := load()
	if _, ok := plain.PublicKey().(*ssh.Certificate); ok {
		t.Fatal("no certificate should be served on first boot")
	}

	// Sign a host certificate for the TPM key, as the backend would.
	hostPub := plain.PublicKey()
	cert := &ssh.Certificate{
		Key:         hostPub,
		CertType:    ssh.HostCert,
		KeyId:       "host-test",
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	certPath := p.TPMHostKeyCert()
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		t.Fatal(err)
	}

	// The reloaded identity presents the certificate.
	certified := load()
	c, ok := certified.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatal("reloaded identity does not serve the host certificate")
	}
	if !bytes.Equal(c.Key.Marshal(), hostPub.Marshal()) {
		t.Fatal("served certificate is for the wrong key")
	}

	// Simulate a TPM clear: the derived key changes. The stale certificate
	// must be dropped (it no longer matches) and a new key served plain.
	sim.Close()
	withSimulatedTPM(t)
	afterClear := load()
	if _, isCert := afterClear.PublicKey().(*ssh.Certificate); isCert {
		t.Fatal("stale certificate must not be served after the TPM key changed")
	}
	if bytes.Equal(afterClear.PublicKey().Marshal(), hostPub.Marshal()) {
		t.Fatal("TPM clear must yield a different host key")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatal("stale certificate file must be removed so the sync re-signs it")
	}
}
