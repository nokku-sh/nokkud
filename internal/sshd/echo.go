package sshd

import "golang.org/x/sys/unix"

// echoEnabled reports whether the pty behind fd currently has ECHO set.
// Password prompts turn echo off. Fails closed so secrets cannot leak.
func echoEnabled(fd uintptr) bool {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return false
	}
	return termios.Lflag&unix.ECHO != 0
}
