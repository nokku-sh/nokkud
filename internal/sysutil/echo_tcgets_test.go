//go:build linux

package sysutil

import (
	"testing"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/unix"
)

// EchoEnabled must track the pty's ECHO flag so recordings can omit input
// while password prompts have echo disabled.
func TestEchoEnabled(t *testing.T) {
	t.Parallel()

	ptmx, err := pty.New()
	if err != nil {
		t.Fatalf("pty.New: %v", err)
	}
	defer func() { _ = ptmx.Close() }()

	fd := ptmx.Fd()
	if !EchoEnabled(fd) {
		t.Fatal("fresh pty should have ECHO set")
	}

	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		t.Fatalf("get termios: %v", err)
	}

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	if err = unix.IoctlSetTermios(int(fd), unix.TCSETS, &noEcho); err != nil {
		t.Fatalf("set termios: %v", err)
	}
	if EchoEnabled(fd) {
		t.Fatal("ECHO cleared but EchoEnabled reports true")
	}

	if err = unix.IoctlSetTermios(int(fd), unix.TCSETS, termios); err != nil {
		t.Fatalf("restore termios: %v", err)
	}
	if !EchoEnabled(fd) {
		t.Fatal("ECHO restored but EchoEnabled reports false")
	}

	// A bogus fd must fail closed (no leak on error).
	if EchoEnabled(^uintptr(0)) {
		t.Fatal("invalid fd must report false")
	}
}
