// Package sysutil provides OS-level helpers for the SSH server: user resolution, session env, shells, disk.
package sysutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// NologinFile is the maintenance lockout file, matching OpenSSH: only root may
// log in while it exists.
const NologinFile = "/etc/nologin"

// LoginAllowed reports whether the user may log in. Root is never blocked, so
// an operator can still get in to fix the machine.
func LoginAllowed(u *user.User, nologinPath string) error {
	if u != nil && u.Uid == "0" {
		return nil
	}
	msg, err := os.ReadFile(nologinPath)
	if err != nil {
		return nil
	}
	if len(bytes.TrimSpace(msg)) == 0 {
		return errors.New("logins are disabled by /etc/nologin")
	}
	return fmt.Errorf("logins are disabled: %s", strings.TrimSpace(string(msg)))
}

// LookupUser resolves a user by name, falling back to getent for NSS / LDAP
// users invisible to static (CGO-less) builds.
func LookupUser(name string) (*user.User, error) {
	if u, err := user.Lookup(name); err == nil {
		return u, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "passwd", name).Output()
	if err != nil {
		return nil, fmt.Errorf("user %q not found", name)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(parts) < 7 {
		return nil, fmt.Errorf("user %q not found", name)
	}
	return &user.User{
		Uid:      parts[2],
		Gid:      parts[3],
		Username: parts[0],
		Name:     parts[4],
		HomeDir:  parts[5],
	}, nil
}

// GroupIDs returns the user's supplementary group ids, falling back to
// `id -G` for NSS / LDAP users invisible to static builds.
func GroupIDs(u *user.User) ([]string, error) {
	if ids, err := u.GroupIds(); err == nil {
		return ids, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "id", "-G", u.Username).Output() // #nosec G204
	if err != nil {
		return nil, fmt.Errorf("lookup groups for %s: %w", u.Username, err)
	}
	return strings.Fields(string(out)), nil
}

// CmdEnv builds the target user's session environment: a fresh HOME/USER/
// SHELL/PATH plus a locale allowlist.
func CmdEnv(sysUser *user.User, shell string) []string {
	envMap := map[string]string{
		"HOME":    sysUser.HomeDir,
		"USER":    sysUser.Username,
		"LOGNAME": sysUser.Username,
		"SHELL":   shell,
		"PATH":    "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}

	// Only innocuous locale/terminal variables are inherited. Connection
	// variables are set per session, so the admin's agent socket cannot leak.
	passThrough := []string{
		"TERM",
		"LANG",
		"LC_ALL",
		"LC_CTYPE",
		"TZ",
		"MAIL",
	}

	for _, key := range passThrough {
		if val, exists := os.LookupEnv(key); exists {
			envMap[key] = val
		}
	}

	if _, exists := envMap["TERM"]; !exists {
		envMap["TERM"] = "xterm-256color"
	}

	var env []string
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	return env
}

// UserShell returns the target user's login shell from the password database.
// The shell is used verbatim, so a lock shell (nologin, false) or a bogus path
// fails the session instead of silently becoming a shell. /bin/sh is used only
// when the password entry carries no shell at all, and never the daemon's own
// SHELL.
func UserShell(u *user.User) string {
	if runtime.GOOS == "windows" {
		if shell := os.Getenv("COMSPEC"); shell != "" {
			return shell
		}
		return "cmd.exe"
	}

	if u != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// #nosec G204
		out, err := exec.CommandContext(ctx, "getent", "passwd", u.Username).Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(out)), ":")
			if len(parts) >= 7 {
				if shell := strings.TrimSpace(parts[6]); shell != "" {
					return shell
				}
			}
		}
	}
	return "/bin/sh"
}
