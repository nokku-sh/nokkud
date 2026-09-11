package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nokkud/internal/paths"

	"golang.org/x/crypto/ssh"
)

var hostKeySalt = []byte("nokku-daemon-host")

// loadHostKeys returns the host identity signer and its closers. The host key
// is not the enrollment anchor, so an identity change is renewed by the sync.
func loadHostKeys() ([]ssh.Signer, []io.Closer, error) {
	signer, err := tpm.NewSigner(tpm.SignerOptions{
		Salt:             hostKeySalt,
		StatePath:        paths.HostSignerStateFile(),
		OnIdentityChange: tpm.RecreateIdentity,
	})
	if err != nil {
		return nil, nil, err
	}

	if err = writeHostPubKey(signer); err != nil {
		_ = signer.Close()
		return nil, nil, err
	}
	removeLegacyHostKeys()

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		_ = signer.Close()
		return nil, nil, fmt.Errorf("sshd: host key signer: %w", err)
	}
	if cert, certErr := parseHostCertFile(paths.HostKeyCert()); certErr == nil {
		if cs, cerr := ssh.NewCertSigner(cert, sshSigner); cerr == nil {
			sshSigner = cs
		}
	}
	return []ssh.Signer{sshSigner}, []io.Closer{signer}, nil
}

// writeHostPubKey persists the public half for the certificate manager. A
// stale certificate from a previous key is dropped and the sync renews it.
func writeHostPubKey(signer tpm.Signer) error {
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("sshd: encode host public key: %w", err)
	}
	pubData := ssh.MarshalAuthorizedKey(pub)

	pubFile := paths.HostKeyPub()
	old, readErr := os.ReadFile(filepath.Clean(pubFile))
	if readErr == nil && bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		return nil
	}

	// #nosec G306 - the public half of the host key is world-readable
	// by design, like any SSH host public key.
	if err = os.WriteFile(pubFile, pubData, 0o644); err != nil {
		return fmt.Errorf("sshd: write host public key: %w", err)
	}
	if readErr == nil {
		_ = os.Remove(paths.HostKeyCert())
	}
	return nil
}

// removeLegacyHostKeys drops the pre-Signer ed25519 identity so it cannot be
// renewed and presented as a second host key.
func removeLegacyHostKeys() {
	_ = os.Remove(paths.SoftwareHostKey())
	_ = os.Remove(paths.SoftwareHostKeyPub())
	_ = os.Remove(paths.SoftwareHostKeyCert())
}

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
