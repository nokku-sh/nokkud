package sshd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestServerAuthorizeHook verifies the Authorize policy hook runs after the
// base cert checks and can deny a login.
func TestServerAuthorizeHook(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
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
	must.NoError(err)
	defer client.Close()
	is.Equal(testPrincipal, gotPrincipal)
}

// TestServerAuthorizeHookDeny verifies a denied login is refused and the
// connection cannot be established.
func TestServerAuthorizeHookDeny(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{
		Authorize: func(ssh.ConnMetadata, *ssh.Certificate, string) error {
			return errors.New("device not trusted")
		},
	})
	defer closeFn()

	_, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	is.Error(err, "login succeeded despite authorize denial")
}

// TestServerForceCommand verifies a certificate force-command critical option
// replaces whatever the client requested, matching sshd.
func TestServerForceCommand(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	// The requested command must be ignored. The forced command runs instead.
	out, err := sess.Output("echo original")
	must.NoError(err)
	is.Equal("forced\n", string(out))
}

// TestServerForceCommandSubsystem verifies a force-command blocks subsystem
// requests (sftp), matching sshd.
func TestServerForceCommandSubsystem(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CriticalOptions = map[string]string{"force-command": "echo forced"}
	}, testPrincipal)

	client, err := dial(t, addr, currentUser(t), auth)
	must.NoError(err)
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = sess.RequestSubsystem("sftp")
	must.Error(err, "subsystem unexpectedly allowed with force-command")
	must.ErrorContains(err, "failed")
}
