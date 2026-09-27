//go:build linux

package sysutil

import (
	"testing"

	"github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// EchoEnabled must track the pty's ECHO flag so recordings can omit input
// while password prompts have echo disabled.
func TestEchoEnabled(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ptmx, err := pty.New()
	must.NoError(err)
	defer func() { _ = ptmx.Close() }()

	fd := ptmx.Fd()
	is.True(EchoEnabled(fd))

	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	must.NoError(err)

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	must.NoError(unix.IoctlSetTermios(int(fd), unix.TCSETS, &noEcho))
	is.False(EchoEnabled(fd))

	must.NoError(unix.IoctlSetTermios(int(fd), unix.TCSETS, termios))
	is.True(EchoEnabled(fd))

	// A bogus fd must fail closed (no leak on error).
	is.False(EchoEnabled(^uintptr(0)))
}
