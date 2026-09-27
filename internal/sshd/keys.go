package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/nokku-sh/mon/tpm"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// loadHostKey returns the host signer, wrapped in the host certificate when
// one matches. The host key is not the enrollment anchor, so an identity
// change just gets a fresh key and the sync renews the cert.
func loadHostKey() (ssh.Signer, io.Closer, error) {
	signer, err := tpm.NewSigner(tpm.SignerOptions{
		// Salt registry: see mon/README.md.
		Salt:             []byte("nokku-daemon-host"),
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
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		_ = signer.Close()
		return nil, nil, fmt.Errorf("sshd: host key signer: %w", err)
	}
	if cert, certErr := parseHostCertFile(paths.HostKeyCert()); certErr == nil {
		if cs, csErr := ssh.NewCertSigner(cert, sshSigner); csErr == nil {
			sshSigner = cs
		}
	}
	return sshSigner, signer, nil
}

// writeHostPubKey persists the public half for the cert renewal. A cert for a
// previous key is dropped so the sync renews it.
func writeHostPubKey(signer tpm.Signer) error {
	pub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("sshd: encode host public key: %w", err)
	}
	pubData := ssh.MarshalAuthorizedKey(pub)

	old, readErr := os.ReadFile(paths.HostKeyPub())
	if readErr == nil && bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(pubData)) {
		return nil
	}
	// #nosec G306 - a host public key is world-readable by design.
	if err = os.WriteFile(paths.HostKeyPub(), pubData, 0o644); err != nil {
		return fmt.Errorf("sshd: write host public key: %w", err)
	}
	if readErr == nil {
		_ = os.Remove(paths.HostKeyCert())
	}
	return nil
}

func parseHostCertFile(path string) (*ssh.Certificate, error) {
	data, err := os.ReadFile(path)
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
