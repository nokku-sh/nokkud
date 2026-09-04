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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	must := require.New(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err, "generate CA key")
	signer, err := ssh.NewSignerFromKey(priv)
	must.NoError(err, "CA signer")
	pub, err := ssh.NewPublicKey(priv.Public())
	must.NoError(err, "CA public key")
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
	must := require.New(t)
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: []string{principal},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}
	must.NoError(cert.SignCert(rand.Reader, ca.signer), "sign cert")
	return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(ca.pub)
}

// writeHostKey drops the software host key pair into dir so the certificate
// logic finds it and returns the public key for signing. Only the .pub half
// is read by the certificate logic.
func writeHostKey(t testing.TB, dir string) ssh.PublicKey {
	t.Helper()
	must := require.New(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err, "generate host key")
	pub, err := ssh.NewPublicKey(priv.Public())
	must.NoError(err, "host public key")
	must.NoError(os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		ssh.MarshalAuthorizedKey(pub),
		0o644,
	), "write host pub")
	must.NoError(os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key"),
		[]byte("unused"),
		0o600,
	), "write host key")
	return pub
}

// newHostPub returns a fresh host public key for signing test certificates.
func newHostPub(t testing.TB) ssh.PublicKey {
	t.Helper()
	must := require.New(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(err, "generate host key")
	pub, err := ssh.NewPublicKey(priv.Public())
	must.NoError(err, "host public key")
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
			is := assert.New(t)
			must := require.New(t)
			dir := t.TempDir()
			tt.setup(t, dir, newTestCA(t))

			t.Setenv("NOKKUD_DATA_DIR", dir)
			pairs, err := OutdatedHostCerts(tt.targetID)
			must.NoError(err, "OutdatedHostCerts")
			is.Len(pairs, tt.want)
		})
	}
}

func TestNextRenewal(t *testing.T) {
	now := time.Now()

	t.Run("no certificates schedules immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1")
		is.False(got.IsZero(), "NextRenewal returned zero time with no certificates")
		is.False(got.After(now.Add(time.Minute)), "NextRenewal = %v, want ~now", got)
	})

	t.Run("expiry drives the schedule", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)

		near := uint64(now.Add(30 * 24 * time.Hour).Unix())
		certText, _ := signHostCert(t, ca, hostPub, "target-1", 0, near)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1")

		want := now.Add(30*24*time.Hour - renewWindowCap)
		is.InDelta(
			float64(want.UnixNano()), float64(got.UnixNano()), float64(time.Minute),
			"NextRenewal = %v, want ~%v", got, want,
		)
	})

	t.Run("short certificates renew late in life, never immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)

		// 7-day TTL (the backend's new host cap) issued one minute ago.
		after := uint64(now.Add(-time.Minute).Unix())
		before := uint64(now.Add(7 * 24 * time.Hour).Unix())
		certText, _ := signHostCert(t, ca, hostPub, "target-1", after, before)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1")

		// 15% of 7 days is ~25.2h, so the deadline sits ~5.95 days out. It
		// must be well after issuance (renew-loop guard) but before the
		// expiry minus one day.
		want := time.Unix(int64(before), 0).Add(-time.Duration(0.15 * float64(7*24*time.Hour)))
		is.InDelta(
			float64(want.UnixNano()), float64(got.UnixNano()), float64(time.Minute),
			"NextRenewal = %v, want ~%v", got, want,
		)
		is.True(got.After(now.Add(5*24*time.Hour)), "NextRenewal = %v, want more than 5 days out", got)
	})

	t.Run("infinity certificate is ignored", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)
		certText, _ := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1")
		is.False(got.After(now.Add(time.Minute)), "NextRenewal with only an infinity cert = %v, want ~now", got)
	})

	t.Run("outdated certificate schedules immediately", func(t *testing.T) {
		is := assert.New(t)
		dir := t.TempDir()
		ca := newTestCA(t)
		hostPub := writeHostKey(t, dir)
		certText, _ := signHostCert(t, ca, hostPub, "wrong-target", 0, ssh.CertTimeInfinity)
		writeCert(t, dir, certText)

		t.Setenv("NOKKUD_DATA_DIR", dir)
		got := NextRenewal("target-1")
		is.False(got.After(now.Add(time.Minute)), "NextRenewal with outdated cert = %v, want ~now", got)
	})
}

func TestRenewHostCertsSignFailure(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	writeHostKey(t, dir)

	t.Setenv("NOKKUD_DATA_DIR", dir)

	calls := 0
	sign := func(_ context.Context, _ KeyPair) (*nokkuv1.SignSSHCertificateResponse, error) {
		calls++
		return nil, errors.New("backend refused")
	}

	renewed, err := RenewHostCerts(context.Background(), "target-1", sign, false)
	must.Error(err, "expected the sign error to be returned")
	is.Equal(0, renewed)
	is.Equal(1, calls)

	// Nothing must have landed on disk.
	_, statErr := os.Stat(paths.SoftwareHostKeyCert())
	must.ErrorIs(statErr, os.ErrNotExist, "failed renewal must not write a certificate")
	_, statErr = os.Stat(paths.UserCAFile())
	must.ErrorIs(statErr, os.ErrNotExist, "failed renewal must not write the CA file")
}

func TestRenewHostCertsForce(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
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

	t.Setenv("NOKKUD_DATA_DIR", dir)

	sign := func(_ context.Context, _ KeyPair) (*nokkuv1.SignSSHCertificateResponse, error) {
		cert, caPub := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		certStr, caStr := string(cert), string(caPub)
		return &nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}, nil
	}

	// A valid cert is not outdated, so a normal renew leaves it alone.
	renewed, err := RenewHostCerts(context.Background(), "target-1", sign, false)
	must.NoError(err, "renew (non-force)")
	is.Equal(0, renewed, "non-force renewed %d certs, want 0", renewed)

	// Force re-signs even the valid cert, refetching the CA.
	renewed, err = RenewHostCerts(context.Background(), "target-1", sign, true)
	must.NoError(err, "renew (force)")
	is.Equal(1, renewed, "force renewed %d certs, want 1", renewed)
}

func TestSaveCertificateRejectsMismatchedCA(t *testing.T) {
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)

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
	err := saveCertificate(res, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"))
	must.Error(err, "saveCertificate accepted a cert signed by a different CA")
	_, statErr := os.Stat(paths.UserCAFile())
	must.ErrorIs(statErr, os.ErrNotExist, "mismatched CA must not write the CA file")
}

// TestSaveCertificateRetiresPreviousCA verifies that switching to a new
// signing CA parks the previous one in the retired file (so the SSH server
// keeps trusting its certificates during the rollover grace window).
func TestSaveCertificateRetiresPreviousCA(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)

	ca1 := newTestCA(t)
	ca2 := newTestCA(t)
	hostPub := writeHostKey(t, dir)
	certPath := filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")

	save := func(ca testCA) {
		t.Helper()
		certText, caText := signHostCert(t, ca, hostPub, "target-1", 0, ssh.CertTimeInfinity)
		certStr, caStr := string(certText), string(caText)
		must.NoError(saveCertificate(&nokkuv1.SignSSHCertificateResponse{
			SignedCertificate: &certStr,
			CaPublicKey:       &caStr,
		}, certPath), "saveCertificate")
	}

	save(ca1)
	active, err := os.ReadFile(paths.UserCAFile())
	must.NoError(err, "read active CA")
	is.Equal(
		bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca1.pub)),
		bytes.TrimSpace(active),
		"active CA file does not hold the first CA",
	)
	_, statErr := os.Stat(paths.RetiredCAFile())
	must.ErrorIs(statErr, os.ErrNotExist, "no retired CA expected after the first save")

	// Saving under a second CA retires the first.
	save(ca2)
	active, err = os.ReadFile(paths.UserCAFile())
	must.NoError(err, "read active CA")
	is.Equal(
		bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca2.pub)),
		bytes.TrimSpace(active),
		"active CA file does not hold the second CA",
	)
	var retired []byte
	retired, err = os.ReadFile(paths.RetiredCAFile())
	must.NoError(err, "read retired CA")
	is.Equal(
		bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca1.pub)),
		bytes.TrimSpace(retired),
		"retired CA file does not hold the first CA",
	)

	// A renewal under the same CA must not retire it again.
	save(ca2)
	_, statErr = os.Stat(paths.RetiredCAFile())
	is.NoError(statErr, "same-CA renewal must leave the retired CA untouched")
}

func writeCert(t testing.TB, dir string, data []byte) {
	t.Helper()
	must := require.New(t)
	must.NoError(os.WriteFile(
		filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"),
		data,
		0o644,
	), "write certificate")
}
