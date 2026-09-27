//go:build !windows

package sysutil

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// SysProcAttr builds session process attributes: a new session, plus a
// credentials drop to the target user and their groups when running as root.
func SysProcAttr(sysUser *user.User) (*syscall.SysProcAttr, error) {
	attr := &syscall.SysProcAttr{Setsid: true}

	// Non-root may not call setgroups(2) even to keep its own groups (EPERM),
	// so Credential here would make every session fail at exec.
	if os.Geteuid() != 0 {
		return attr, nil
	}

	uid, err := strconv.ParseUint(sysUser.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse uid for user %s: %w", sysUser.Username, err)
	}

	gid, err := strconv.ParseUint(sysUser.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gid for user %s: %w", sysUser.Username, err)
	}

	groupIDs, err := GroupIDs(sysUser)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup groups for user %s: %w", sysUser.Username, err)
	}

	var subGroups []uint32
	for _, g := range groupIDs {
		var id uint64
		id, err = strconv.ParseUint(g, 10, 32)
		if err != nil {
			slog.Debug("parse supplementary group id", "group", g, "error", err)
			continue
		}
		subGroups = append(subGroups, uint32(id))
	}

	attr.Credential = &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: subGroups,
	}
	return attr, nil
}
