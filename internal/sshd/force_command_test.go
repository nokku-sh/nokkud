package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

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

	out, err := sess.Output("echo original")
	must.NoError(err)
	is.Equal("forced\n", string(out))
}

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
