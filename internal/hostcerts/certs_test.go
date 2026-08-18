package hostcerts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

type testCA struct {
	pub    ssh.PublicKey
	signer ssh.Signer
}

func newTestCA(t testing.TB) testCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
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

// signHostCert signs a host certificate for hostPub with the given validity
// window and returns its authorized_keys text plus the CA's.
func signHostCert(
	t testing.TB,
	ca testCA,
	hostPub ssh.PublicKey,
	principal string,
	validAfter, validBefore uint64,
) (certText, caText []byte) {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: []string{principal},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(ca.pub)
}

// writeHostKey drops the software host key pair into dir so the certificate
// logic finds it and returns the public key for signing. Only the .pub half
// is read by the certificate logic.
func writeHostKey(t testing.TB, dir string) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}
	if err = os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		ssh.MarshalAuthorizedKey(pub),
		0o644,
	); err != nil {
		t.Fatalf("write host pub: %v", err)
	}
	if err = os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key"),
		[]byte("unused"),
		0o600,
	); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	return pub
}

// newHostPub returns a fresh host public key for signing test certificates.
func newHostPub(t testing.TB) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("host public key: %v", err)
	}
	return pub
}

func TestOutdatedHostCerts(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		setup    func(t *testing.T, dir string, ca testCA)
		targetID string
		want     int
	}{
		{
			name: "missing certificate is outdated",
			setup: func(t *testing.T, dir string, _ testCA) {
				writeHostKey(t, dir)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "certificate for another principal is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText, _ := signHostCert(t, ca, hostPub, "other-target", 0, ssh.CertTimeInfinity)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "expiring certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText, _ := signHostCert(
					t, ca, hostPub, "target-1", 0, uint64(now.Add(24*time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "expired certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText, _ := signHostCert(
					t,
					ca,
					hostPub,
					"target-1",
					0,
					uint64(now.Add(-time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "valid certificate is not outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				hostPub := writeHostKey(t, dir)
				certText, _ := signHostCert(
					t, ca, hostPub, "target-1", uint64(now.Add(-time.Hour).Unix()),
					uint64(now.Add(90*24*time.Hour).Unix()),
				)
				writeCert(t, dir, certText)
			},
			targetID: "target-1",
			want:     0,
		},
		{
			name:     "no keys means nothing to renew",
			setup:    func(_ *testing.T, _ string, _ testCA) {},
			targetID: "target-1",
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir, newTestCA(t))

			p := paths.Paths{ConfigDir: dir}
			pairs, err := OutdatedHostCerts(p, tt.targetID)
			if err != nil {
				t.Fatalf("OutdatedHostCerts: %v", err)
			}
			if len(pairs) != tt.want {
				t.Fatalf("OutdatedHostCerts returned %d pairs, want %d", len(pairs), tt.want)
			}
		})
	}
}

func TestNextRenewal(t *testing.T) {
	now := time.Now()

	t.Run("no certificates schedules immediately", func(t *testing.T) {
		dir := t.TempDir()
		p := paths.Paths{ConfigDir: dir}
		got := NextRenewal(p, "target-1")
		if got.IsZero() {
			t.Fatal("NextRenewal returned zero time with no certificates")
		}
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal = %v, want ~now", got)
		}
	})

	t.Run("expiry drives the schedule", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)

		near := uint64(now.Add(30 * 24 * time.Hour).Unix())
		certText, _ := signHostCert(t, ca, hostPub, "target-1", 0, near)
		writeCert(t, dir, certText)

		p := paths.Paths{ConfigDir: dir}
		got := NextRenewal(p, "target-1")

		want := now.Add(30*24*time.Hour - renewBeforeExpiry)
		if got.Sub(want) > time.Minute || want.Sub(got) > time.Minute {
			t.Fatalf("NextRenewal = %v, want ~%v", got, want)
		}
	})

	t.Run("infinity certificate is ignored", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)
		certText, _ := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		p := paths.Paths{ConfigDir: dir}
		got := NextRenewal(p, "target-1")
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal with only an infinity cert = %v, want ~now", got)
		}
	})

	t.Run("outdated certificate schedules immediately", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)
		certText, _ := signHostCert(t, ca, hostPub, "wrong-target", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		p := paths.Paths{ConfigDir: dir}
		got := NextRenewal(p, "target-1")
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal with outdated cert = %v, want ~now", got)
		}
	})
}

func TestRenewHostCertsSignFailure(t *testing.T) {
	dir := t.TempDir()
	writeHostKey(t, dir)

	p := paths.Paths{ConfigDir: dir}

	calls := 0
	sign := func(_ context.Context, _ KeyPair) (*nokkuv1.SignSSHCertificateResponse, error) {
		calls++
		return nil, errors.New("backend refused")
	}

	renewed, err := RenewHostCerts(context.Background(), p, "target-1", sign, false)
	if err == nil {
		t.Fatal("expected the sign error to be returned")
	}
	if renewed != 0 {
		t.Fatalf("renewed = %d, want 0", renewed)
	}
	if calls != 1 {
		t.Fatalf("sign called %d times, want 1", calls)
	}

	// Nothing must have landed on disk.
	if _, statErr := os.Stat(p.SoftwareHostKeyCert()); !os.IsNotExist(statErr) {
		t.Fatalf("failed renewal must not write a certificate: %v", statErr)
	}
	if _, statErr := os.Stat(p.UserCAFile()); !os.IsNotExist(statErr) {
		t.Fatalf("failed renewal must not write the CA file: %v", statErr)
	}
}

func TestRenewHostCertsForce(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	hostPub := writeHostKey(t, dir)

	now := time.Now()
	certText, _ := signHostCert(
		t, ca, hostPub, "target-1",
		uint64(now.Add(-time.Hour).Unix()),
		uint64(now.Add(90*24*time.Hour).Unix()),
	)
	writeCert(t, dir, certText)

	p := paths.Paths{ConfigDir: dir}

	sign := func(_ context.Context, _ KeyPair) (*nokkuv1.SignSSHCertificateResponse, error) {
		cert, caPub := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		certStr, caStr := string(cert), string(caPub)
		return &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}, nil
	}

	// A valid cert is not outdated, so a normal renew leaves it alone.
	renewed, err := RenewHostCerts(context.Background(), p, "target-1", sign, false)
	if err != nil {
		t.Fatalf("renew (non-force): %v", err)
	}
	if renewed != 0 {
		t.Fatalf("non-force renewed %d certs, want 0", renewed)
	}

	// Force re-signs even the valid cert, refetching the CA.
	renewed, err = RenewHostCerts(context.Background(), p, "target-1", sign, true)
	if err != nil {
		t.Fatalf("renew (force): %v", err)
	}
	if renewed != 1 {
		t.Fatalf("force renewed %d certs, want 1", renewed)
	}
}

func TestSaveCertificateRejectsMismatchedCA(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{ConfigDir: dir}

	ca := newTestCA(t)
	otherCA := newTestCA(t)
	hostPub := writeHostKey(t, dir)
	certText, _ := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
	_, otherCaText := signHostCert(t, otherCA, hostPub, "target-1", 0, ssh.CertTimeInfinity)

	certStr, caStr := string(certText), string(otherCaText)
	res := &nokkuv1.SignSSHCertificateResponse{
		SignedCertificate: &certStr,
		CaPublicKey:       &caStr,
	}
	err := saveCertificate(p, res, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"))
	if err == nil {
		t.Fatal("saveCertificate accepted a cert signed by a different CA")
	}
	if _, statErr := os.Stat(p.UserCAFile()); !os.IsNotExist(statErr) {
		t.Fatal("mismatched CA must not write the CA file")
	}
}

// TestSaveCertificateRetiresPreviousCA verifies that switching to a new
// signing CA parks the previous one in the retired file (so the SSH server
// keeps trusting its certificates during the rollover grace window).
func TestSaveCertificateRetiresPreviousCA(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{ConfigDir: dir}

	ca1 := newTestCA(t)
	ca2 := newTestCA(t)
	hostPub := writeHostKey(t, dir)
	certPath := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")

	save := func(ca testCA) {
		t.Helper()
		certText, caText := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		certStr, caStr := string(certText), string(caText)
		if err := saveCertificate(p, &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}, certPath); err != nil {
			t.Fatalf("saveCertificate: %v", err)
		}
	}

	save(ca1)
	active, err := os.ReadFile(p.UserCAFile())
	if err != nil {
		t.Fatalf("read active CA: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(active), bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca1.pub))) {
		t.Fatal("active CA file does not hold the first CA")
	}
	if _, statErr := os.Stat(p.RetiredCAFile()); !os.IsNotExist(statErr) {
		t.Fatal("no retired CA expected after the first save")
	}

	// Saving under a second CA retires the first.
	save(ca2)
	active, err = os.ReadFile(p.UserCAFile())
	if err != nil {
		t.Fatalf("read active CA: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(active), bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca2.pub))) {
		t.Fatal("active CA file does not hold the second CA")
	}
	retired, err := os.ReadFile(p.RetiredCAFile())
	if err != nil {
		t.Fatalf("read retired CA: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(retired), bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca1.pub))) {
		t.Fatal("retired CA file does not hold the first CA")
	}

	// A renewal under the same CA must not retire it again.
	save(ca2)
	if _, statErr := os.Stat(p.RetiredCAFile()); statErr != nil {
		t.Fatal("same-CA renewal must leave the retired CA untouched")
	}
}

func writeCert(t testing.TB, dir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
		data,
		0o644,
	); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
}
