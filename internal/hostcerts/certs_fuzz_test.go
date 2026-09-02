package hostcerts

import (
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// FuzzParseCertificate feeds arbitrary bytes into the certificate parser that
// consumes control-plane responses. It must never panic, only accept host
// certificates, and any certificate it does accept must round-trip through
// authorized_keys serialization and never crash the renewal/validity checks.
func FuzzParseCertificate(f *testing.F) {
	ca := newTestCA(f)
	certText, _ := signHostCert(f, ca, newHostPub(f), "some-target-id", 0, ssh.CertTimeInfinity)
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
	ca := newTestCA(f)
	certText, caText := signHostCert(
		f,
		ca,
		newHostPub(f),
		"some-target-id",
		0,
		ssh.CertTimeInfinity,
	)
	f.Add(certText, caText)
	f.Add([]byte("garbage"), []byte("garbage"))
	f.Add([]byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, signedCert, caPub []byte) {
		t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
		certPath := paths.SoftwareHostKeyCert()

		certStr, caStr := string(signedCert), string(caPub)
		res := &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}
		err := saveCertificate(res, certPath)
		if err != nil {
			return
		}

		// Success means the CA file must be a parseable authorized key and
		// the certificate file must parse back to a certificate.
		caData, err := os.ReadFile(paths.UserCAFile())
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
