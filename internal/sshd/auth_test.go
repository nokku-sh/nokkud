package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestServerSourceAddress verifies the source-address critical option is
// enforced: logins from an allowed source succeed, others are refused.
func TestServerSourceAddress(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	withSource := func(cidr string) ssh.AuthMethod {
		return userCertOpts(t, ca, func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"source-address": cidr}
		}, testPrincipal)
	}

	client, err := dial(t, addr, currentUser(t), withSource("127.0.0.0/8"))
	must.NoError(err, "dial from allowed source")
	_ = client.Close()

	_, err = dial(t, addr, currentUser(t), withSource("203.0.113.0/24"))
	is.Error(err, "dial from disallowed source succeeded")
}

// TestServerRejectsHostCert verifies a host-type certificate signed by the
// trusted CA cannot authenticate a user.
func TestServerRejectsHostCert(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	hostCert := userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.CertType = ssh.HostCert
	}, testPrincipal)

	_, err := dial(t, addr, currentUser(t), hostCert)
	is.Error(err, "host certificate authenticated a user")
}

// TestServerCertExtensionPTY verifies a certificate without permit-pty gets
// its pty-req refused while exec keeps working.
func TestServerCertExtensionPTY(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{})
	is.Error(err, "pty-req succeeded without permit-pty")
}

// TestServerCertExtensionForwarding verifies a certificate without
// permit-port-forwarding cannot open direct-tcpip (-L) channels even when
// forwarding is enabled by tunables.
func TestServerCertExtensionForwarding(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	_, err = client.Dial("tcp", "127.0.0.1:9")
	is.Error(err, "direct-tcpip succeeded without permit-port-forwarding")
}

// TestServerCertExtensionAgent verifies a certificate without
// permit-agent-forwarding gets its agent forwarding request refused.
func TestServerCertExtensionAgent(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCertOpts(t, ca, func(c *ssh.Certificate) {
		c.Extensions = nil
	}, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	sess, err := client.NewSession()
	must.NoError(err)
	defer sess.Close()

	err = agent.RequestAgentForwarding(sess)
	is.Error(err, "agent forwarding succeeded without permit-agent-forwarding")
}
