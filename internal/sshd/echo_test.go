package sshd

import (
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// echoEnabled must track the pty's ECHO flag so recordings can omit input
// while password prompts have echo disabled.
func TestEchoEnabled(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	ptmx, tty, err := pty.Open()
	must.NoError(err)
	defer ptmx.Close()
	defer tty.Close()

	fd := ptmx.Fd()
	is.True(echoEnabled(fd))

	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	must.NoError(err)

	noEcho := *termios
	noEcho.Lflag &^= unix.ECHO
	must.NoError(unix.IoctlSetTermios(int(fd), unix.TCSETS, &noEcho))
	is.False(echoEnabled(fd))

	must.NoError(unix.IoctlSetTermios(int(fd), unix.TCSETS, termios))
	is.True(echoEnabled(fd))

	// A bogus fd must fail closed (no leak on error).
	is.False(echoEnabled(^uintptr(0)))
}
