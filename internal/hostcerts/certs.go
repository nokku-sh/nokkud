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
	"github.com/nokku-sh/nokkud/internal/util"
)

const renewBeforeExpiry = 7 * 24 * time.Hour

// KeyPair is a host public key paired with the certificate path that backs it.
type KeyPair struct {
	PublicKeyPath string
	CertPath      string
	PublicKeyData []byte
}

// OutdatedHostCerts returns the host keys whose certificate is missing,
// signed for another principal, or within renewBeforeExpiry of expiring.
func (m *Manager) OutdatedHostCerts(targetID string) ([]KeyPair, error) {
	privKeys, err := m.paths.PrivateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list private keys: %w", err)
	}

	var toSign []KeyPair
	for _, privFile := range privKeys {
		pubFile := privFile + ".pub"
		certFile := privFile + "-cert.pub"

		var pubBytes []byte
		pubBytes, err = os.ReadFile(filepath.Clean(pubFile))
		if err != nil {
			continue
		}

		var cert *ssh.Certificate
		cert, err = parseCertificate(certFile)
		if err != nil || !isValid(cert, targetID) {
			toSign = append(toSign, KeyPair{
				PublicKeyPath: pubFile,
				CertPath:      certFile,
				PublicKeyData: pubBytes,
			})
		}
	}
	return toSign, nil
}

// RenewHostCerts signs and stores a fresh certificate for every outdated
// host key via sign. Returns the count; failures are logged and the first
// one returned.
func (m *Manager) RenewHostCerts(
	ctx context.Context,
	targetID string,
	sign func(context.Context, KeyPair) (*nokkuv1.SignSSHCertificateResponse, error),
) (int, error) {
	pairs, err := m.OutdatedHostCerts(targetID)
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
		if err = m.saveCertificate(res, kp.CertPath); err != nil {
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

// NextRenewal returns the earliest renewal deadline across host certs
// (now, if any is already out of date).
func (m *Manager) NextRenewal(targetID string) time.Time {
	var earliest time.Time
	now := time.Now()

	matches, err := m.paths.Certificates()
	if err != nil {
		slog.Debug("list certificates", "error", err)
		return now
	}

	for _, path := range matches {
		var cert *ssh.Certificate
		cert, err = parseCertificate(path)
		if err != nil {
			slog.Debug("parse certificate", "path", path, "error", err)
			continue
		}
		if !isValid(cert, targetID) {
			return now
		}
		if cert.ValidBefore == ssh.CertTimeInfinity {
			continue
		}
		renewalTime := uint64ToUnixTime(cert.ValidBefore).Add(-renewBeforeExpiry)
		if earliest.IsZero() || renewalTime.Before(earliest) {
			earliest = renewalTime
		}
	}

	if !earliest.IsZero() {
		slog.Debug(
			"certificate renewal scheduled",
			"next_renewal",
			time.Until(earliest).Round(time.Second),
		)
	}
	return earliest
}

// saveCertificate verifies the cert was signed by the returned CA key,
// then stores both where the embedded SSH server reads them.
func (m *Manager) saveCertificate(res *nokkuv1.SignSSHCertificateResponse, path string) error {
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

	if err = util.WriteIfChanged(m.paths.UserCAFile(), caPubKey, 0o644); err != nil {
		return fmt.Errorf("write user CA: %w", err)
	}

	if err = util.WriteIfChanged(path, ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

// isValid reports whether cert is acceptable for targetID and not within
// renewBeforeExpiry of expiring.
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
	expiresAt := uint64ToUnixTime(cert.ValidBefore)
	return now.Before(expiresAt.Add(-renewBeforeExpiry))
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
