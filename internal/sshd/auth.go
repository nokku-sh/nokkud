package sshd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/paths"
)

var errNoCertificates = errors.New("sshd: only certificate authentication is supported")

// retiredCAGrace is how long the previously trusted CA remains accepted after
// a rollover, so user certificates it signed keep working until they expire
// (the backend's default user TTLs are at most 7 days).
const retiredCAGrace = 8 * 24 * time.Hour

// loadTrustedCAs reads every CA public key from the daemon's cached CA files.
// The active CA plus, within retiredCAGrace of the rollover, the retired one.
func loadTrustedCAs() ([]ssh.PublicKey, error) {
	userCA := paths.UserCAFile()
	keys, err := parseCAFile(userCA)
	if err != nil {
		return nil, err
	}

	// Best-effort. A corrupt or missing retired file must never take down
	// authentication, which the active CA still provides.
	retiredCA := paths.RetiredCAFile()
	if st, statErr := os.Stat(retiredCA); statErr == nil {
		if time.Since(st.ModTime()) < retiredCAGrace {
			if retired, parseErr := parseCAFile(retiredCA); parseErr == nil {
				keys = append(keys, retired...)
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("sshd: no CA public keys found in %s", userCA)
	}
	return keys, nil
}

// parseCAFile parses every authorized-key line from path.
func parseCAFile(path string) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
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
// principals are subject UUIDs. A principal is accepted when it is in the
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

	allowed := s.principals(conn.User())
	if len(allowed) == 0 {
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

	// Reuses x/crypto/ssh's validation for critical options, the validity
	// window, and the CA signature. The source-address critical option is
	// enforced by the SSH stack itself. The checker is built per-auth so CA
	// reloads apply to new connections immediately.
	checker := ssh.CertChecker{
		IsUserAuthority:          s.trustedCA,
		SupportedCriticalOptions: []string{"force-command"},
	}
	if err := checker.CheckCert(matched, cert); err != nil {
		return nil, s.deny(conn, err)
	}

	// Post-auth policy hook. Device trust, MFA, workspace membership, or any
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
	// so the exec path can enforce it (listed as supported above).
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
