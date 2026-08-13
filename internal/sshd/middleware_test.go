package sshd

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestServerAuthorizeHook verifies the Authorize policy hook runs after the
// base cert checks and can deny a login.
func TestServerAuthorizeHook(t *testing.T) {
	var gotPrincipal string
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{
		Authorize: func(_ ssh.ConnMetadata, _ *ssh.Certificate, principal string) error {
			gotPrincipal = principal
			return nil
		},
	})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if gotPrincipal != testPrincipal {
		t.Fatalf("authorize got principal %q, want %q", gotPrincipal, testPrincipal)
	}
}

// TestServerAuthorizeHookDeny verifies a denied login is refused and the
// connection cannot be established.
func TestServerAuthorizeHookDeny(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{
		Authorize: func(ssh.ConnMetadata, *ssh.Certificate, string) error {
			return errors.New("device not trusted")
		},
	})
	defer closeFn()

	if _, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal)); err == nil {
		t.Fatal("login succeeded despite authorize denial")
	}
}

// TestServerForceCommand verifies a certificate force-command critical option
// replaces whatever the client requested, matching sshd.
func TestServerForceCommand(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	// The requested command must be ignored. The forced command runs instead.
	out, err := sess.Output("echo original")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "forced\n" {
		t.Fatalf("output = %q, want %q", out, "forced\n")
	}
}

// TestServerForceCommandSubsystem verifies a force-command blocks subsystem
// requests (sftp), matching sshd.
func TestServerForceCommandSubsystem(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err = sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("subsystem unexpectedly allowed with force-command")
	} else if !strings.Contains(err.Error(), "failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
