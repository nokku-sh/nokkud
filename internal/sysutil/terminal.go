// Package sysutil provides OS-level helpers for the SSH server: user resolution, session env, shells, disk.
package sysutil

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NologinFile is the maintenance lockout file, matching OpenSSH: only root may
// log in while it exists.
const NologinFile = "/etc/nologin"

// Account is a local account as the password database has it.
type Account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

// LoginAllowed reports whether the account may log in. Root is never blocked,
// so an operator can still get in to fix the machine.
func LoginAllowed(a *Account, nologinPath string) error {
	if a.UID == 0 {
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

// LookupAccount resolves a local account through getent, so NSS and LDAP
// users resolve too. A static binary cannot see those on its own.
func LookupAccount(name string) (*Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 - name passed the principals lookup, which only holds valid usernames.
	out, err := exec.CommandContext(ctx, "getent", "passwd", name).Output()
	if err != nil {
		return nil, fmt.Errorf("user %q not found", name)
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ":")
	// getent takes a number as a uid. The entry has to be the name asked for.
	if len(parts) != 7 || parts[0] != name {
		return nil, fmt.Errorf("user %q not found", name)
	}
	uid, uidErr := strconv.ParseUint(parts[2], 10, 32)
	gid, gidErr := strconv.ParseUint(parts[3], 10, 32)
	if uidErr != nil || gidErr != nil {
		return nil, fmt.Errorf("user %q has a bad passwd entry", name)
	}
	return &Account{
		Name: name,
		UID:  uint32(uid),
		GID:  uint32(gid),
		Home: parts[5],
		// The shell is used as it stands, so a lock shell (nologin, false)
		// fails the session. Only an empty field means /bin/sh.
		Shell: cmp.Or(parts[6], "/bin/sh"),
	}, nil
}

// groupIDs returns the account's supplementary group ids.
func groupIDs(a *Account) ([]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "id", "-G", a.Name).Output() // #nosec G204
	if err != nil {
		return nil, fmt.Errorf("lookup groups for %s: %w", a.Name, err)
	}
	var ids []uint32
	for g := range strings.FieldsSeq(string(out)) {
		id, parseErr := strconv.ParseUint(g, 10, 32)
		if parseErr != nil {
			return nil, fmt.Errorf("lookup groups for %s: %w", a.Name, parseErr)
		}
		ids = append(ids, uint32(id))
	}
	return ids, nil
}

// CmdEnv builds the account's session environment: a fresh HOME/USER/
// SHELL/PATH plus a locale allowlist. TERM is the session's to set.
func CmdEnv(a *Account) []string {
	envMap := map[string]string{
		"HOME":    a.Home,
		"USER":    a.Name,
		"LOGNAME": a.Name,
		"SHELL":   a.Shell,
		"PATH":    "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}

	// Only innocuous locale variables are inherited. Connection variables are
	// set per session, so the admin's agent socket cannot leak.
	passThrough := []string{
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

	var env []string
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	return env
}
