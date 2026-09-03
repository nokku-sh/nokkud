// Package hostcerts manages the host SSH certificate lifecycle. It signs
// host keys against the backend and stores certs and the trusted CA where
// the embedded SSH server reads them.
package hostcerts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// renewFraction and renewWindowCap define the renewal window as a share of
// the certificate's validity, capped at the historical fixed offset. A
// fraction instead of a fixed window so short-lived certificates (the
// backend now caps host TTLs at 7 days) never sit inside the window from
// the moment they are issued, which would turn the renewal watcher into a
// loop.
const (
	renewFraction  = 0.15
	renewWindowCap = 7 * 24 * time.Hour
)

// renewalDeadline returns the moment cert enters its renewal window.
func renewalDeadline(cert *ssh.Certificate) time.Time {
	validAfter := uint64ToUnixTime(cert.ValidAfter)
	validBefore := uint64ToUnixTime(cert.ValidBefore)
	window := min(time.Duration(float64(validBefore.Sub(validAfter))*renewFraction), renewWindowCap)
	return validBefore.Add(-window)
}

// KeyPair is a host public key paired with the certificate path that backs it.
type KeyPair struct {
	PublicKeyPath string
	CertPath      string
	PublicKeyData []byte
}

// hostKeyPair returns the active host key. The TPM-backed key when it exists,
// otherwise the on-disk software key. ok is false when no host key exists yet
// (e.g. the SSH server has never started).
func hostKeyPair() (KeyPair, bool) {
	for _, c := range []struct{ pub, cert string }{
		{paths.TPMHostKeyPub(), paths.TPMHostKeyCert()},
		{paths.SoftwareHostKeyPub(), paths.SoftwareHostKeyCert()},
	} {
		data, readErr := os.ReadFile(filepath.Clean(c.pub))
		if readErr != nil {
			continue
		}
		return KeyPair{
			PublicKeyPath: c.pub,
			CertPath:      c.cert,
			PublicKeyData: data,
		}, true
	}
	return KeyPair{}, false
}

// OutdatedHostCerts returns the host key when its certificate is missing,
// signed for another principal, signed for another key, or inside its
// renewal window.
func OutdatedHostCerts(targetID string) ([]KeyPair, error) {
	kp, ok := hostKeyPair()
	if !ok {
		return nil, nil
	}

	cert, parseErr := parseCertificate(kp.CertPath)
	if parseErr != nil || !isValid(cert, targetID) || !matchesKey(cert, kp) {
		return []KeyPair{kp}, nil
	}
	return nil, nil
}

// matchesKey reports whether the certificate was issued for the key in kp.
// A certificate for a previous key (e.g. after a TPM clear or replacement)
// must be re-issued even though its validity window is still fine.
func matchesKey(cert *ssh.Certificate, kp KeyPair) bool {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(kp.PublicKeyData))
	if err != nil {
		return false
	}
	return bytes.Equal(cert.Key.Marshal(), pub.Marshal())
}

// RenewHostCerts signs and stores a fresh certificate for the host key via
// sign. When force is set, the key is re-signed regardless of validity. That
// is used after a CA rollover to refetch the CA and re-sign the host identity
// under the new authority. Returns the count. Failures are logged and the
// first one returned.
func RenewHostCerts(
	ctx context.Context,
	targetID string,
	sign func(context.Context, KeyPair) (*nokkuv1.SignSSHCertificateResponse, error),
	force bool,
) (int, error) {
	var pairs []KeyPair
	var err error
	if force {
		if kp, ok := hostKeyPair(); ok {
			pairs = []KeyPair{kp}
		}
	} else {
		pairs, err = OutdatedHostCerts(targetID)
	}
	if err != nil {
		return 0, err
	}

	var firstErr error
	renewed := 0
	for _, kp := range pairs {
		var res *nokkuv1.SignSSHCertificateResponse
		res, err = sign(ctx, kp)
		if err != nil {
			slog.Warn("sign host key", "error", err, "key", kp.PublicKeyPath)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err = saveCertificate(res, kp.CertPath); err != nil {
			slog.Warn("failed to save host certificate", "path", kp.CertPath, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		renewed++
	}
	return renewed, firstErr
}

// NextRenewal returns the renewal deadline for the host certificate: 85%
// through its validity (capped at 7 days before expiry). Now, if it is
// already out of date or none exists yet.
func NextRenewal(targetID string) time.Time {
	now := time.Now()

	kp, ok := hostKeyPair()
	if !ok {
		return now
	}
	cert, err := parseCertificate(kp.CertPath)
	if err != nil {
		slog.Debug("parse certificate", "path", kp.CertPath, "error", err)
		return now
	}
	if !isValid(cert, targetID) {
		return now
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return now
	}

	renewalTime := renewalDeadline(cert)
	if renewalTime.Before(now) {
		return now
	}
	slog.Debug(
		"certificate renewal scheduled",
		"next_renewal",
		time.Until(renewalTime).Round(time.Second),
	)
	return renewalTime
}

// saveCertificate verifies the cert was signed by the returned CA key,
// then stores both where the embedded SSH server reads them.
func saveCertificate(res *nokkuv1.SignSSHCertificateResponse, path string) error {
	signedCert := bytes.TrimSpace([]byte(res.GetSignedCertificate()))
	caPubKey := bytes.TrimSpace([]byte(res.GetCaPublicKey()))

	cert, err := parseCertificateBytes(signedCert)
	if err != nil {
		return err
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubKey)
	if err != nil {
		return err
	}

	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		return errors.New("invalid signature: certificate not signed by provided CA")
	}

	// A new signing CA. Park the current one before switching so the SSH
	// server can keep trusting certificates it signed during the rollover
	// grace window (see sshd.loadTrustedCAs). The retired file's mtime is
	// stamped with the retirement time so the grace window starts at the
	// rollover, not when the old CA was last written.
	userCA := paths.UserCAFile()
	retiredCA := paths.RetiredCAFile()
	if current, readErr := os.ReadFile(userCA); readErr == nil &&
		!bytes.Equal(bytes.TrimSpace(current), caPubKey) {
		if renameErr := os.Rename((userCA), retiredCA); renameErr != nil {
			return fmt.Errorf("retire previous CA: %w", renameErr)
		}
		now := time.Now()
		if err = os.Chtimes(retiredCA, now, now); err != nil {
			return fmt.Errorf("stamp retired CA: %w", err)
		}
	}

	if err = util.WriteIfChanged(userCA, caPubKey, 0o644); err != nil {
		return fmt.Errorf("write user CA: %w", err)
	}

	if err = util.WriteIfChanged(path, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

// isValid reports whether cert is acceptable for targetID and not yet due
// for renewal.
func isValid(cert *ssh.Certificate, targetID string) bool {
	now := time.Now()

	if targetID != "" {
		if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != targetID {
			return false
		}
	}
	if now.Before(uint64ToUnixTime(cert.ValidAfter)) {
		return false
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return true
	}
	return now.Before(renewalDeadline(cert))
}

func parseCertificateBytes(data []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil {
		return nil, err
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}

	if cert.CertType != ssh.HostCert {
		return nil, fmt.Errorf("not a host certificate (type %d)", cert.CertType)
	}
	return cert, nil
}

func parseCertificate(path string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return parseCertificateBytes(data)
}

func uint64ToUnixTime(t uint64) time.Time {
	if t > math.MaxInt64 {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(int64(t), 0)
}
