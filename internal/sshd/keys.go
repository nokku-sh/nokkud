package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

// hostKeySalt namespaces the TPM key derivation for the SSH host identity.
// It must stay different from the request-signing salts ("nokku-daemon",
// "nokku-cli") so each purpose derives a distinct key from the same TPM.
var hostKeySalt = []byte("nokku-host")

// openHostKeyTPM opens the TPM-resident host key. It is a variable so tests
// can point it at the TPM simulator.
var openHostKeyTPM = tpm.OpenKey

// loadHostKeys returns the daemon's host identity signers and any resources
// to release when they are swapped out or the server shuts down. On machines
// with a TPM 2.0 the host key is TPM-resident (the private key never touches
// disk); everywhere else an ed25519 key is generated in the state directory.
func loadHostKeys(p paths.Paths) ([]ssh.Signer, []io.Closer, error) {
	s, closer, tpmErr := loadTPMHostKey(p)
	if tpmErr == nil {
		return []ssh.Signer{s}, []io.Closer{closer}, nil
	}
	slog.Debug("sshd: tpm host key unavailable, using software key", "error", tpmErr)

	signers, err := loadSoftwareHostKeys(p)
	if err != nil {
		return nil, nil, err
	}
	return signers, nil, nil
}

// loadSoftwareHostKeys returns the daemon's on-disk host identity, generating
// an ed25519 key on first boot. The TPM is never consulted.
func loadSoftwareHostKeys(p paths.Paths) ([]ssh.Signer, error) {
	if s, err := loadHostKey(p.SoftwareHostKey()); err == nil {
		return []ssh.Signer{s}, nil
	}

	s, err := generateHostKey(p)
	if err != nil {
		return nil, err
	}
	return []ssh.Signer{s}, nil
}

// loadTPMHostKey derives the TPM-resident host key, persisting only its
// public half in the state directory. The returned closer releases the TPM
// handle when the signer is no longer needed. On success any software host
// key from before the TPM migration is removed so the daemon presents a
// single identity.
func loadTPMHostKey(p paths.Paths) (ssh.Signer, io.Closer, error) {
	key, err := openHostKeyTPM(hostKeySalt)
	if err != nil {
		return nil, nil, err
	}

	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		_ = key.Close()
		return nil, nil, fmt.Errorf("sshd: tpm host key signer: %w", err)
	}

	pubFile := p.TPMHostKeyPub()
	pubData := ssh.MarshalAuthorizedKey(signer.PublicKey())

	// The public half is persisted so the certificate manager can sign it
	// and so a TPM clear or replacement (new derived key) is detected.
	if old, readErr := os.ReadFile(filepath.Clean(pubFile)); readErr != nil ||
		!bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		// #nosec G306 - the public half of the host key is world-readable
		// by design, like any SSH host public key.
		if err = os.WriteFile(pubFile, pubData, 0o644); err != nil {
			_ = key.Close()
			return nil, nil, fmt.Errorf("sshd: write tpm host public key: %w", err)
		}
		// The identity changed (first boot, TPM cleared or replaced): any
		// certificate for the previous key is stale and would be rejected
		// by NewCertSigner anyway. Drop it so the sync renews it.
		_ = os.Remove(p.TPMHostKeyCert())
	}

	// A software host key from before the TPM migration must not linger: it
	// would be renewed and presented as a second identity.
	_ = os.Remove(p.SoftwareHostKey())
	_ = os.Remove(p.SoftwareHostKeyPub())
	_ = os.Remove(p.SoftwareHostKeyCert())

	// Present the host certificate alongside the key when one exists.
	if cert, certErr := parseHostCertFile(p.TPMHostKeyCert()); certErr == nil {
		if cs, cerr := ssh.NewCertSigner(cert, signer); cerr == nil {
			signer = cs
		}
	}

	return signer, key, nil
}

// loadHostKey parses a private key and, when a matching "-cert.pub" exists,
// presents the host certificate alongside it (like sshd).
func loadHostKey(privFile string) (ssh.Signer, error) {
	data, err := os.ReadFile(filepath.Clean(privFile))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}

	cert, err := parseHostCertFile(privFile + "-cert.pub")
	if err != nil {
		return signer, nil
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return signer, nil
	}
	return cs, nil
}

// parseHostCertFile reads certPath and returns the certificate inside, or an
// error when it is missing or not a host certificate.
func parseHostCertFile(certPath string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("sshd: not a certificate")
	}
	return cert, nil
}

// generateHostKey creates an ed25519 host key and persists it in the daemon's
// state directory so the host identity survives restarts (including restarts
// while the backend is unreachable).
func generateHostKey(p paths.Paths) (ssh.Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshd: generate host key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("sshd: encode host public key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshd: marshal host private key: %w", err)
	}
	keyFile := p.SoftwareHostKey()
	if err = os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("sshd: write host key: %w", err)
	}
	// #nosec G306 - the public half of the host key is world-readable by
	// design, like any SSH host public key.
	if err = os.WriteFile(keyFile+".pub",
		ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return nil, fmt.Errorf("sshd: write host public key: %w", err)
	}

	return ssh.NewSignerFromKey(priv)
}
