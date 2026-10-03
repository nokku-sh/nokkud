package sshd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// retiredCAGrace keeps certificates signed by a rolled-over CA valid until
// they expire (user TTLs are at most 7 days).
const retiredCAGrace = 8 * 24 * time.Hour

var errNoCertificates = errors.New("sshd: only certificate authentication is supported")

// loadTrustedCAs returns the active CA public keys plus, within retiredCAGrace
// of a rollover, the retired CA. With dropRetired the retired CA is not trusted
// and its file is removed, so trust cannot come back.
func loadTrustedCAs(dropRetired bool) ([]ssh.PublicKey, error) {
	userCA := paths.UserCAFile()
	keys, err := parseCAFile(userCA)
	if err != nil {
		return nil, err
	}

	// Best-effort. A corrupt or missing retired file must never take down
	// authentication, which the active CA still provides.
	retiredCA := paths.RetiredCAFile()
	if dropRetired {
		if removeErr := os.Remove(retiredCA); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			slog.Debug("remove retired CA", "error", removeErr)
		}
	} else if st, statErr := os.Stat(retiredCA); statErr == nil {
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

// parseCAFile parses every authorized-key line in path, skipping blanks and
// comments.
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

// caKeys indexes CA public keys by wire encoding so lookups never marshal on
// the auth path.
func caKeys(keys []ssh.PublicKey) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[string(k.Marshal())] = struct{}{}
	}
	return set
}

func (s *Server) trustedCA(key ssh.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.trustedCAs[string(key.Marshal())]
	return ok
}

// publicKeyCallback authenticates a user certificate whose principals are
// subject UUIDs.
func (s *Server) publicKeyCallback(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, s.deny(conn, errNoCertificates)
	}
	// CheckCert does not validate the cert type, so a host certificate from a
	// shared or misconfigured CA would otherwise authenticate a user.
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

	// Built per-auth so CA reloads apply to new connections immediately.
	// x/crypto/ssh enforces the critical options, validity window, and CA
	// signature.
	checker := ssh.CertChecker{
		IsUserAuthority:          s.trustedCA,
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(matched, cert); err != nil {
		return nil, s.deny(conn, err)
	}

	// CriticalOptions are enforced by the stack, Extensions by the session.
	// A hand-built cert can have a nil Extensions map, which panics on write.
	perms := &ssh.Permissions{
		CriticalOptions: maps.Clone(cert.CriticalOptions),
		Extensions:      maps.Clone(cert.Extensions),
	}
	if perms.Extensions == nil {
		perms.Extensions = make(map[string]string, 2)
	}
	perms.Extensions["nokku-principal"] = matched
	// The key id is covered by the CA signature, so the session can trust it
	// to tell a control-plane web session from a direct login.
	perms.Extensions["nokku-cert-key-id"] = cert.KeyId
	if fc := cert.CriticalOptions["force-command"]; fc != "" {
		perms.Extensions["force-command"] = fc
	}
	return perms, nil
}

// accountKey is where the login's local account sits in the permissions.
const accountKey = "nokku-account"

// verifiedPublicKey finishes the login once the client proved it holds the
// key. publicKeyCallback also answers key queries, which prove nothing. The
// local account is checked here and not per channel, so a missing account or
// /etc/nologin stops forwards as well as sessions.
func (s *Server) verifiedPublicKey(
	conn ssh.ConnMetadata,
	_ ssh.PublicKey,
	perms *ssh.Permissions,
	_ string,
) (*ssh.Permissions, error) {
	sysUser, err := sysutil.LookupUser(conn.User())
	if err == nil {
		err = sysutil.LoginAllowed(sysUser, s.nologinFile)
	}
	if err != nil {
		return nil, s.deny(conn, err)
	}
	perms.ExtraData = map[any]any{accountKey: sysUser}

	ev := connEvent(conn, eventAuthSuccess)
	ev.Principal = perms.Extensions["nokku-principal"]
	s.emit(ev)
	return perms, nil
}

// certExt reports whether the certificate carries the named extension. Absent
// means deny.
func certExt(conn *ssh.ServerConn, name string) bool {
	if conn == nil || conn.Permissions == nil {
		return false
	}
	_, ok := conn.Permissions.Extensions[name]
	return ok
}

// deny audits and logs a rejected login, then returns err.
func (s *Server) deny(conn ssh.ConnMetadata, err error) error {
	ev := connEvent(conn, eventAuthFailure)
	ev.Error = err.Error()
	s.emit(ev)
	slog.Warn("auth denied",
		"user", conn.User(), "remote", conn.RemoteAddr(), "client", string(conn.ClientVersion()), "error", err)
	return err
}
