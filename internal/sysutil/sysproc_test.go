//go:build !windows

package sysutil

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Non-root processes must never set Credential: Go calls setgroups(2)
// whenever Credential is non-nil, and setgroups requires CAP_SETGID, so
// every session sshd spawns as a regular user would fail with EPERM.
func TestSysProcAttrNoCredentialWhenNonRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("test must run as a non-root user")
	}

	is := assert.New(t)
	must := require.New(t)

	u := &user.User{
		Uid:      strconv.Itoa(os.Getuid()),
		Gid:      strconv.Itoa(os.Getgid()),
		Username: "testuser",
	}

	attr, err := SysProcAttr(u)
	must.NoError(err)
	is.Nil(attr.Credential)
	is.True(attr.Setsid)

	// End-to-end: the attribute set must actually spawn as this user.
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = attr
	is.NoError(cmd.Run())
}

func TestSysProcAttrCredentialWhenRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() != 0 {
		t.Skip("test must run as root")
	}

	is := assert.New(t)
	must := require.New(t)

	u := &user.User{Uid: "0", Gid: "0", Username: "root"}
	attr, err := SysProcAttr(u)
	must.NoError(err)
	is.NotNil(attr.Credential)
}
