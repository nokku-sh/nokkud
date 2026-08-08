//go:build darwin || freebsd || netbsd || openbsd

package sysutil

import "golang.org/x/sys/unix"

// EchoEnabled reports whether the pty behind fd currently has ECHO set.
// Password prompts (sudo, su, passwd, ssh) turn echo off, so recorders use
// this to skip input while it is hidden. It fails closed (false) so an
// error can never leak a secret into a recording.
func EchoEnabled(fd uintptr) bool {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	if err != nil {
		return false
	}
	return termios.Lflag&unix.ECHO != 0
}
