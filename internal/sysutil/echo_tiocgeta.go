//go:build darwin || freebsd || netbsd || openbsd

package sysutil

import "golang.org/x/sys/unix"

// EchoEnabled reports whether the pty behind fd currently has ECHO set.
// Password prompts turn echo off. Fails closed so secrets cannot leak.
func EchoEnabled(fd uintptr) bool {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	if err != nil {
		return false
	}
	return termios.Lflag&unix.ECHO != 0
}
