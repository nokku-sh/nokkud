package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/paths"
)

var errNoCertificates = errors.New("sshd: only certificate authentication is supported")

// loadTrustedCAs reads every CA public key from the daemon's cached CA file.
func loadTrustedCAs(p paths.Paths) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(p.UserCAFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("sshd: no cached CA public key at %s", p.UserCAFile())
		}
		return nil, fmt.Errorf("sshd: read CA public key: %w", err)
	}

	var keys []ssh.PublicKey
	for len(data) > 0 {
		pub, _, _, rest, parseErr := ssh.ParseAuthorizedKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf("sshd: parse CA public key: %w", parseErr)
		}
		keys = append(keys, pub)
		data = rest
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("sshd: no CA public keys found in %s", p.UserCAFile())
	}
	return keys, nil
}

// trustedCA reports whether key is one of the configured CAs.
func (s *Server) trustedCA(key ssh.PublicKey) bool {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()
	blob := key.Marshal()
	for _, ca := range s.trustedCAs {
		if bytes.Equal(blob, ca.Marshal()) {
			return true
		}
	}
	return false
}

// publicKeyCallback authenticates a user certificate. The certificate
// principals are subject UUIDs; a principal is accepted when it is in the
// cached allowed set for the requested local username.
func (s *Server) publicKeyCallback(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, s.deny(conn, errNoCertificates)
	}

	if !s.trustedCA(cert.SignatureKey) {
		return nil, s.deny(conn, errors.New("sshd: certificate signed by unrecognized authority"))
	}

	allowed, ok := s.principals(conn.User())
	if !ok || len(allowed) == 0 {
		return nil, s.deny(conn, fmt.Errorf("sshd: no access rules for user %q", conn.User()))
	}

	matched := ""
	for _, p := range allowed {
		if slices.Contains(cert.ValidPrincipals, p) {
			matched = p
			break
		}
	}
	if matched == "" {
		return nil, s.deny(
			conn,
			fmt.Errorf("sshd: certificate principal not authorized for user %q", conn.User()),
		)
	}

	// Reuses x/crypto/ssh's validation: critical options, validity window
	// and the CA signature. The source-address critical option is enforced
	// by the SSH stack itself. The checker is built per-auth so CA reloads
	// apply to new connections immediately.
	checker := ssh.CertChecker{
		IsUserAuthority:          s.trustedCA,
		SupportedCriticalOptions: []string{"force-command"},
	}
	if err := checker.CheckCert(matched, cert); err != nil {
		return nil, s.deny(conn, err)
	}

	// Post-auth policy hook: device trust, MFA, workspace membership, or any
	// extension enforcement layered on top of the base checks.
	if s.authorize != nil {
		if err := s.authorize(conn, cert, matched); err != nil {
			return nil, s.deny(conn, fmt.Errorf("sshd: login denied by policy: %w", err))
		}
	}

	perms := &ssh.Permissions{
		Extensions: map[string]string{
			"nokku-principal": matched,
		},
	}

	// Carry the certificate's force-command critical option into the session
	// so the exec path can enforce it (it is now listed as supported above).
	if fc := cert.CriticalOptions["force-command"]; fc != "" {
		perms.Extensions["force-command"] = fc
	}

	s.emit(eventWith(connEvent(conn), audit.EventAuthSuccess, matched, ""))
	return perms, nil
}

// deny logs a rejected auth attempt and returns err to the caller. Every
// denial flows through here so there is a single audit/log point.
func (s *Server) deny(conn ssh.ConnMetadata, err error) error {
	ev := eventWith(connEvent(conn), audit.EventAuthFailure, "", err.Error())
	s.emit(ev)
	s.authFailure(conn, err)
	return err
}

// authFailure logs a denied auth attempt for audit purposes.
func (s *Server) authFailure(conn ssh.ConnMetadata, err error) {
	s.logger.Warn(
		"sshd: auth denied",
		"user", conn.User(),
		"remote", conn.RemoteAddr(),
		"client", string(conn.ClientVersion()),
		"error", err,
	)
}
