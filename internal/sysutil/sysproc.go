package sysutil

import (
	"os"
	"syscall"
)

// SysProcAttr builds session process attributes: a new session, plus a
// credentials drop to the account and its groups when running as root.
func SysProcAttr(a *Account) (*syscall.SysProcAttr, error) {
	attr := &syscall.SysProcAttr{Setsid: true}

	// Non-root may not call setgroups(2) even to keep its own groups (EPERM),
	// so Credential here would make every session fail at exec.
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
