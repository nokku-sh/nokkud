package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// loadHostKeys returns the daemon's host identity signers from its state
// directory, generating an ed25519 key there on first boot. The daemon owns
// its host keys; the system sshd's keys in /etc/ssh are never read.
func loadHostKeys(p paths.Paths) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	load := func(names []string) {
		for _, f := range names {
			s, err := loadHostKey(f)
			if err != nil {
				continue
			}
			signers = append(signers, s)
		}
	}

	if privs, err := p.PrivateKeys(); err == nil {
		load(privs)
	}

	if len(signers) == 0 {
		s, err := generateHostKey(p)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	return signers, nil
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

	certFile := privFile + "-cert.pub"
	if !util.FileExists(certFile) {
		return signer, nil
	}
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return signer, nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return signer, nil
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return signer, nil
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return signer, nil
	}
	return cs, nil
}

// generateHostKey creates an ed25519 host key and persists it in the daemon's
// state directory so the host identity survives restarts (including restarts
// while the backend is unreachable) and is picked up by the host certificate
// renewer (paths.PrivateKeys glob).
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
	keyFile := filepath.Join(p.ConfigDir, "ssh_host_ed25519_key")
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
