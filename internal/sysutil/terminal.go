// Package sysutil provides OS-level helpers for the SSH server: user and
// group resolution (getent fallbacks), session env, shells, disk checks.
package sysutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// LookupUser resolves a user by name, falling back to getent so NSS / LDAP
// users still work in static (CGO-less) builds where os/user only reads /etc/passwd.
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

// CmdEnv builds the target user's session environment: a fresh
// HOME/USER/SHELL/PATH plus a locale/terminal allowlist. Connection
// variables like SSH_AUTH_SOCK are set per session by the caller, so
// one user's session cannot leak the admin's agent socket.
func CmdEnv(sysUser *user.User, shell string) []string {
	envMap := map[string]string{
		"HOME":    sysUser.HomeDir,
		"USER":    sysUser.Username,
		"LOGNAME": sysUser.Username,
		"SHELL":   shell,
		"PATH":    "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}

	// Only innocuous locale/terminal variables are inherited from the daemon's
	// own environment. Connection-scoped variables (SSH_CONNECTION, SSH_TTY,
	// SSH_AUTH_SOCK) are set per session by the caller; inheriting them would
	// leak the enrolling admin's agent socket and connection details into
	// other users' sessions (the documented enrollment flow starts the daemon
	// from an interactive SSH session). X11 is not supported, so DISPLAY and
	// XAUTHORITY are never set either.
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

// UserShell resolves the user's login shell (getent, then SHELL, then
// /bin/sh; COMSPEC on Windows), used only if it is executable.
func UserShell(u *user.User) string {
	if runtime.GOOS == "windows" {
		if shell := os.Getenv("COMSPEC"); shell != "" {
			return shell
		}
		return "cmd.exe"
	}

	// resolve the target user's shell from the password database.
	if u != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// #nosec G204
		out, err := exec.CommandContext(ctx, "getent", "passwd", u.Username).Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(out)), ":")
			if len(parts) >= 7 {
				shell := strings.TrimSpace(parts[6])
				if shell != "" && IsExecutable(shell) {
					return shell
				}
			}
		}
	}

	// fall back to the caller's SHELL, then /bin/sh
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}
	return "/bin/sh"
}

// IsExecutable checks whether path is a regular file with execute permission.
// It uses stat(2) instead of [exec.LookPath] because the path is always absolute.
func IsExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}
