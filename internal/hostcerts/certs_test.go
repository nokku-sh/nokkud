package hostcerts

import (
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

// signHostCert signs a host certificate for principal with the given
// validity window and returns its authorized_keys text plus the CA's.
func signHostCert(
	t testing.TB,
	ca testCA,
	principal string,
	validAfter, validBefore uint64,
) (certText, caText []byte) {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             ca.pub,
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

// writeHostKey drops an ssh_host_*_key pair into dir so paths.PrivateKeys
// finds it. Only the .pub half is read by the certificate logic.
func writeHostKey(t testing.TB, dir, name string) {
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
		filepath.Join(dir, name+".pub"),
		ssh.MarshalAuthorizedKey(pub),
		0o644,
	); err != nil {
		t.Fatalf("write host pub: %v", err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), []byte("unused"), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
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
				writeHostKey(t, dir, "ssh_host_ed25519_key")
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "certificate for another principal is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				writeHostKey(t, dir, "ssh_host_ed25519_key")
				certText, _ := signHostCert(t, ca, "other-target", 0, ssh.CertTimeInfinity)
				writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "expiring certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				writeHostKey(t, dir, "ssh_host_ed25519_key")
				certText, _ := signHostCert(
					t, ca, "target-1", 0, uint64(now.Add(24*time.Hour).Unix()),
				)
				writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "expired certificate is outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				writeHostKey(t, dir, "ssh_host_ed25519_key")
				certText, _ := signHostCert(
					t,
					ca,
					"target-1",
					0,
					uint64(now.Add(-time.Hour).Unix()),
				)
				writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)
			},
			targetID: "target-1",
			want:     1,
		},
		{
			name: "valid certificate is not outdated",
			setup: func(t *testing.T, dir string, ca testCA) {
				writeHostKey(t, dir, "ssh_host_ed25519_key")
				certText, _ := signHostCert(
					t, ca, "target-1", uint64(now.Add(-time.Hour).Unix()),
					uint64(now.Add(90*24*time.Hour).Unix()),
				)
				writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)
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

			m := New(paths.Paths{ConfigDir: dir})
			pairs, err := m.OutdatedHostCerts(tt.targetID)
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
		m := New(paths.Paths{ConfigDir: dir})
		got := m.NextRenewal("target-1")
		if got.IsZero() {
			t.Fatal("NextRenewal returned zero time with no certificates")
		}
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal = %v, want ~now", got)
		}
	})

	t.Run("earliest expiry wins", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		writeHostKey(t, dir, "ssh_host_ed25519_key")

		far := uint64(now.Add(60 * 24 * time.Hour).Unix())
		certText, _ := signHostCert(t, ca, "target-1", 0, far)
		writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)

		writeHostKey(t, dir, "ssh_host_ecdsa_key")
		near := uint64(now.Add(30 * 24 * time.Hour).Unix())
		certText2, _ := signHostCert(t, ca, "target-1", 0, near)
		writeFile(t, dir, "ssh_host_ecdsa_key-cert.pub", certText2)

		m := New(paths.Paths{ConfigDir: dir})
		got := m.NextRenewal("target-1")

		want := now.Add(30*24*time.Hour - renewBeforeExpiry)
		if got.Sub(want) > time.Minute || want.Sub(got) > time.Minute {
			t.Fatalf("NextRenewal = %v, want ~%v", got, want)
		}
	})

	t.Run("infinity certificate is ignored", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		writeHostKey(t, dir, "ssh_host_ed25519_key")
		certText, _ := signHostCert(t, ca, "target-1", 0, ssh.CertTimeInfinity)
		writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)

		m := New(paths.Paths{ConfigDir: dir})
		got := m.NextRenewal("target-1")
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal with only an infinity cert = %v, want ~now", got)
		}
	})

	t.Run("outdated certificate schedules immediately", func(t *testing.T) {
		dir := t.TempDir()
		ca := newTestCA(t)
		writeHostKey(t, dir, "ssh_host_ed25519_key")
		certText, _ := signHostCert(t, ca, "wrong-target", 0, ssh.CertTimeInfinity)
		writeFile(t, dir, "ssh_host_ed25519_key-cert.pub", certText)

		m := New(paths.Paths{ConfigDir: dir})
		got := m.NextRenewal("target-1")
		if got.After(now.Add(time.Minute)) {
			t.Fatalf("NextRenewal with outdated cert = %v, want ~now", got)
		}
	})
}

func TestRenewHostCertsPartialFailure(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	writeHostKey(t, dir, "ssh_host_ed25519_key")
	writeHostKey(t, dir, "ssh_host_ecdsa_key")

	now := time.Now()
	m := New(paths.Paths{ConfigDir: dir})

	calls := 0
	sign := func(_ context.Context, kp KeyPair) (*nokkuv1.SignSSHCertificateResponse, error) {
		calls++
		// Fail for the ed25519 key, succeed for the ecdsa key.
		if filepath.Base(kp.PublicKeyPath) == "ssh_host_ed25519_key.pub" {
			return nil, errors.New("backend refused")
		}
		certText, caText := signHostCert(
			t,
			ca,
			"target-1",
			0,
			uint64(now.Add(90*24*time.Hour).Unix()),
		)
		certStr, caStr := string(certText), string(caText)
		return &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}, nil
	}

	renewed, err := m.RenewHostCerts(context.Background(), "target-1", sign)
	if err == nil {
		t.Fatal("expected the first error to be returned")
	}
	if renewed != 1 {
		t.Fatalf("renewed = %d, want 1 (failures must not stop other keys)", renewed)
	}
	if calls != 2 {
		t.Fatalf("sign called %d times, want 2", calls)
	}

	// The successful pair must have landed on disk.
	if _, statErr := os.Stat(filepath.Join(dir, "ssh_host_ecdsa_key-cert.pub")); statErr != nil {
		t.Fatalf("successful certificate not saved: %v", statErr)
	}
	if _, statErr := os.Stat(m.paths.UserCAFile()); statErr != nil {
		t.Fatalf("CA file not saved: %v", statErr)
	}
}

func TestSaveCertificateRejectsMismatchedCA(t *testing.T) {
	dir := t.TempDir()
	m := New(paths.Paths{ConfigDir: dir})

	ca := newTestCA(t)
	otherCA := newTestCA(t)
	certText, _ := signHostCert(t, ca, "target-1", 0, ssh.CertTimeInfinity)
	_, otherCaText := signHostCert(t, otherCA, "target-1", 0, ssh.CertTimeInfinity)

	certStr, caStr := string(certText), string(otherCaText)
	res := &nokkuv1.SignSSHCertificateResponse{
		SignedCertificate: &certStr,
		CaPublicKey:       &caStr,
	}
	err := m.saveCertificate(res, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"))
	if err == nil {
		t.Fatal("saveCertificate accepted a cert signed by a different CA")
	}
	if _, statErr := os.Stat(m.paths.UserCAFile()); !os.IsNotExist(statErr) {
		t.Fatal("mismatched CA must not write the CA file")
	}
}

func writeFile(t testing.TB, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
