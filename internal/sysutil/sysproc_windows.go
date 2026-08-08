//go:build windows

package sysutil

import (
	"os/user"
	"syscall"
)

// SysProcAttr returns the default attributes; Windows needs no user drop.
func SysProcAttr(_ *user.User) (*syscall.SysProcAttr, error) {
	return &syscall.SysProcAttr{}, nil
}
