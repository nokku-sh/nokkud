//go:build !windows

package sysutil

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"testing"
)

// Non-root processes must never set Credential: Go calls setgroups(2)
// whenever Credential is non-nil, and setgroups requires CAP_SETGID, so
// every session sshd spawns as a regular user would fail with EPERM.
func TestSysProcAttrNoCredentialWhenNonRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("test must run as a non-root user")
	}

	u := &user.User{
		Uid:      strconv.Itoa(os.Getuid()),
		Gid:      strconv.Itoa(os.Getgid()),
		Username: "testuser",
	}

	attr, err := SysProcAttr(u)
	if err != nil {
		t.Fatalf("SysProcAttr: %v", err)
	}
	if attr.Credential != nil {
		t.Fatal("Credential must be nil for non-root processes (setgroups EPERM)")
	}
	if !attr.Setsid {
		t.Fatal("Setsid must stay enabled for pty sessions")
	}

	// End-to-end: the attribute set must actually spawn as this user.
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = attr
	if err = cmd.Run(); err != nil {
		t.Fatalf("spawn with SysProcAttr failed: %v", err)
	}
}

func TestSysProcAttrCredentialWhenRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() != 0 {
		t.Skip("test must run as root")
	}

	u := &user.User{Uid: "0", Gid: "0", Username: "root"}
	attr, err := SysProcAttr(u)
	if err != nil {
		t.Fatalf("SysProcAttr: %v", err)
	}
	if attr.Credential == nil {
		t.Fatal("root daemon must keep Credential to drop privileges")
	}
}
