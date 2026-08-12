package hostcerts

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// seedCertText builds a self-signed certificate plus its CA public key in
// authorized_keys format, used as the valid seed for the fuzzers.
func seedCertText(t testing.TB) (certText, caText []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	caPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("CA public key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             caPub,
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: []string{"some-target-id"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err = cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(caPub)
}

// FuzzParseCertificate feeds arbitrary bytes into the certificate parser that
// consumes control-plane responses. It must never panic, only accept host
// certificates, and any certificate it does accept must round-trip through
// authorized_keys serialization and never crash the renewal/validity checks.
func FuzzParseCertificate(f *testing.F) {
	certText, _ := seedCertText(f)
	f.Add(certText)
	f.Add([]byte(""))
	f.Add([]byte("not a key"))
	f.Add([]byte("ssh-ed25519 AAAA"))
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----"))

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := parseCertificateBytes(data)
		if err != nil {
			return
		}
		if cert.CertType != ssh.HostCert {
			t.Fatalf(
				"parseCertificateBytes accepted cert with type %d, want %d",
				cert.CertType,
				ssh.HostCert,
			)
		}
		if _, _, _, _, err = ssh.ParseAuthorizedKey(ssh.MarshalAuthorizedKey(cert)); err != nil {
			t.Fatalf("accepted certificate does not round-trip: %v", err)
		}
		_ = isValid(cert, "")
		_ = isValid(cert, "some-target-id")
	})
}

// FuzzSaveCertificate drives the store path end to end: certificate + CA text
// from the control plane against a scratch dir. Any accepted pair must leave
// parseable files behind, and nothing may panic.
func FuzzSaveCertificate(f *testing.F) {
	certText, caText := seedCertText(f)
	f.Add(certText, caText)
	f.Add([]byte("garbage"), []byte("garbage"))
	f.Add([]byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, signedCert, caPub []byte) {
		p := paths.Paths{ConfigDir: t.TempDir()}
		m := New(p)
		certPath := filepath.Join(p.ConfigDir, "ssh_host_ed25519_key-cert.pub")

		certStr, caStr := string(signedCert), string(caPub)
		res := &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}
		err := m.saveCertificate(res, certPath)
		if err != nil {
			return
		}

		// Success means the CA file must be a parseable authorized key and
		// the certificate file must parse back to a certificate.
		caData, err := os.ReadFile(p.UserCAFile())
		if err != nil {
			t.Fatalf("saveCertificate succeeded but CA file is unreadable: %v", err)
		}
		if _, _, _, _, err = ssh.ParseAuthorizedKey(caData); err != nil {
			t.Fatalf("saveCertificate wrote unparseable CA: %v", err)
		}
		certData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("saveCertificate succeeded but cert file is unreadable: %v", err)
		}
		if _, err = parseCertificateBytes(certData); err != nil {
			t.Fatalf("saveCertificate wrote unparseable cert: %v", err)
		}
	})
}
