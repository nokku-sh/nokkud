package sshd

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
	"syscall"
	"time"
)

// Matching OpenSSH, only root may log in while this file exists.
const nologinPath = "/etc/nologin"

type account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

// Root is never blocked, so an operator can still get in to fix the machine.
func loginAllowed(a *account, nologinPath string) error {
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

// getent resolves NSS and LDAP users too, a static binary cannot see those on its own.
func lookupAccount(name string) (*account, error) {
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
	return &account{
		Name: name,
		UID:  uint32(uid),
		GID:  uint32(gid),
		Home: parts[5],
		// A lock shell (nologin, false) is used as is and fails the session. Only an empty field means /bin/sh.
		Shell: cmp.Or(parts[6], "/bin/sh"),
	}, nil
}

func groupIDs(a *account) ([]uint32, error) {
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

func cmdEnv(a *account) []string {
	env := []string{
		"HOME=" + a.Home,
		"USER=" + a.Name,
		"LOGNAME=" + a.Name,
		"SHELL=" + a.Shell,
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
	}
	// Only harmless locale variables are inherited, so the admin's agent socket cannot leak.
	for _, key := range []string{"LANG", "LC_ALL", "LC_CTYPE", "TZ", "MAIL"} {
		if val, exists := os.LookupEnv(key); exists {
			env = append(env, key+"="+val)
		}
	}
	return env
}

func sysProcAttr(a *account) (*syscall.SysProcAttr, error) {
	attr := &syscall.SysProcAttr{Setsid: true}

	// Non-root gets EPERM from setgroups(2) even for its own groups, so Credential would fail every exec.
	if os.Geteuid() != 0 {
		return attr, nil
	}
	groups, err := groupIDs(a)
	if err != nil {
		return nil, err
	}
	attr.Credential = &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: groups}
	return attr, nil
}
