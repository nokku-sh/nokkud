package sshd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"maps"
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

// parseCAFile parses every authorized-key line from path. Blank lines and
// comments are skipped, matching the authorized_keys format the file mirrors.
func parseCAFile(path string) ([]ssh.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sshd: read CA public key: %w", err)
	}
	defer f.Close()

	var keys []ssh.PublicKey
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		pub, _, _, _, parseErr := ssh.ParseAuthorizedKey(line)
		if parseErr != nil {
			return nil, fmt.Errorf("sshd: parse CA public key: %w", parseErr)
		}
		keys = append(keys, pub)
	}
	if scanErr := scan.Err(); scanErr != nil {
		return nil, fmt.Errorf("sshd: read CA public key: %w", scanErr)
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
	// CheckCert does not validate the cert type (only CertChecker.Authenticate
	// does), so a host certificate from a shared or misconfigured CA would
	// otherwise authenticate a user.
	if cert.CertType != ssh.UserCert {
		return nil, s.deny(conn, fmt.Errorf("sshd: certificate has type %d, want user certificate", cert.CertType))
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
	// window, and the CA signature. source-address is enforced by the stack
	// against the CriticalOptions this callback returns below. The checker is
	// built per-auth so CA reloads apply to new connections immediately.
	checker := ssh.CertChecker{
		IsUserAuthority:          s.trustedCA,
		SupportedCriticalOptions: []string{"force-command", "source-address"},
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

	// CriticalOptions flow to the stack, which enforces source-address and
	// exposes force-command to the session. Extensions flow to the session so
	// it can enforce the permit-* options (absent means deny, matching sshd).
	// Wire-parsed certs always carry an Extensions map; hand-built ones may
	// not, and writing into a nil map would panic inside the auth callback.
	perms := &ssh.Permissions{
		CriticalOptions: maps.Clone(cert.CriticalOptions),
		Extensions:      maps.Clone(cert.Extensions),
	}
	if perms.Extensions == nil {
		perms.Extensions = make(map[string]string, 2)
	}
	perms.Extensions["nokku-principal"] = matched
	if fc := cert.CriticalOptions["force-command"]; fc != "" {
		perms.Extensions["force-command"] = fc
	}

	s.emit(eventWith(connEvent(conn), audit.EventAuthSuccess, matched, ""))
	return perms, nil
}

// certExt reports whether the authenticated certificate carries the named
// extension. Absent means deny, matching sshd's permit-* semantics.
func certExt(conn *ssh.ServerConn, name string) bool {
	if conn == nil || conn.Permissions == nil {
		return false
	}
	_, ok := conn.Permissions.Extensions[name]
	return ok
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
