// Package hostcerts manages the host SSH certificate lifecycle for the embedded SSH server.
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

	"github.com/nokku-sh/mon/fsutil"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// The renewal window is a fraction of validity, capped at the historical
// offset, so short-lived certs never start inside it and spin the watcher.
const (
	renewFraction  = 0.15
	renewWindowCap = 7 * 24 * time.Hour
)

// KeyPair is a host public key and the certificate path that backs it.
type KeyPair struct {
	PublicKeyPath string
	CertPath      string
	PublicKeyData []byte
}

// hostKeyPair returns the active host key, or ok false when no host key exists
// yet. The identity is ECDSA P-256 in both TPM-resident and software modes.
func hostKeyPair() (KeyPair, bool) {
	pub := paths.HostKeyPub()
	data, err := os.ReadFile(filepath.Clean(pub))
	if err != nil {
		return KeyPair{}, false
	}
	return KeyPair{
		PublicKeyPath: pub,
		CertPath:      paths.HostKeyCert(),
		PublicKeyData: data,
	}, true
}

// OutdatedHostCerts returns the host key when its certificate is missing,
// signed for another principal or key, or inside its renewal window.
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

// matchesKey reports whether the certificate was issued for the key in kp. A
// cert for a previous key must be re-issued even within its validity window.
func matchesKey(cert *ssh.Certificate, kp KeyPair) bool {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(kp.PublicKeyData))
	if err != nil {
		return false
	}
	return bytes.Equal(cert.Key.Marshal(), pub.Marshal())
}

// RenewHostCerts signs and stores a fresh certificate for the host key via
// sign, reporting whether one was written. force re-signs after a CA rollover.
func RenewHostCerts(
	ctx context.Context,
	targetID string,
	sign func(context.Context, KeyPair) (*nokkuv1.SignSSHCertificateResponse, error),
	force bool,
) (bool, error) {
	var kp KeyPair
	if force {
		var ok bool
		if kp, ok = hostKeyPair(); !ok {
			return false, nil
		}
	} else {
		pairs, err := OutdatedHostCerts(targetID)
		if err != nil {
			return false, err
		}
		if len(pairs) == 0 {
			return false, nil
		}
		kp = pairs[0]
	}

	res, err := sign(ctx, kp)
	if err != nil {
		return false, err
	}
	if err = saveCertificate(res, kp.CertPath); err != nil {
		return false, err
	}
	return true, nil
}

// NextRenewal returns the renewal deadline for the host certificate, or now
// if it is already out of date or none exists.
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
	return renewalTime
}

// saveCertificate verifies the cert was signed by the returned CA key, then
// stores it and the CA where the embedded SSH server reads them.
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

	// New CA: retire the current file before overwriting so the SSH server
	// keeps trusting certs it signed, stamped now for the mtime grace window.
	userCA := paths.UserCAFile()
	retiredCA := paths.RetiredCAFile()
	if current, readErr := os.ReadFile(userCA); readErr == nil &&
		!bytes.Equal(bytes.TrimSpace(current), caPubKey) {
		// Write before overwriting: renaming the old CA away first would
		// leave no active CA and deny all logins until the next sync.
		if err = fsutil.WriteIfChanged(retiredCA, bytes.TrimSpace(current), 0o644); err != nil {
			return fmt.Errorf("retire previous CA: %w", err)
		}
		now := time.Now()
		if err = os.Chtimes(retiredCA, now, now); err != nil {
			return fmt.Errorf("stamp retired CA: %w", err)
		}
	}

	if err = fsutil.WriteIfChanged(userCA, caPubKey, 0o644); err != nil {
		return fmt.Errorf("write user CA: %w", err)
	}

	if err = fsutil.WriteIfChanged(path, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

// isValid reports whether cert is acceptable for targetID and not yet due for
// renewal.
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

// renewalDeadline returns the moment cert enters its renewal window.
func renewalDeadline(cert *ssh.Certificate) time.Time {
	validAfter := uint64ToUnixTime(cert.ValidAfter)
	validBefore := uint64ToUnixTime(cert.ValidBefore)
	window := min(time.Duration(float64(validBefore.Sub(validAfter))*renewFraction), renewWindowCap)
	return validBefore.Add(-window)
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
