package sshd

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestServerMaxConnections verifies the concurrent connection cap: an
// over-cap connection is refused immediately.
func TestServerMaxConnections(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{MaxConnections: 1}})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	defer c1.Close()

	// A second connection while the first is live must be refused.
	_, err = dial(t, addr, user, auth)
	must.Error(err, "second connection unexpectedly accepted")

	// Closing the first frees a slot (server notices asynchronously).
	c1.Close()
	is.Eventually(func() bool {
		c2, derr := dial(t, addr, user, auth)
		if derr == nil {
			c2.Close()
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "connection cap never released")
}

// TestServerMaxStartups verifies the pre-auth connection cap: a half-open
// connection (never completing the handshake) holds a slot and a second
// connection is refused until it frees it.
func TestServerMaxStartups(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{MaxStartups: 1}})
	defer closeFn()

	// A raw TCP connection that never completes the SSH handshake holds the
	// single pre-auth slot.
	nc, err := net.Dial("tcp", addr)
	must.NoError(err)
	defer nc.Close()
	// Give the server time to accept and take the slot.
	time.Sleep(100 * time.Millisecond)

	// A real SSH dial must be refused while the slot is held.
	_, err = dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.Error(err, "dial succeeded while the pre-auth slot was held")

	// Closing the half-open connection frees the slot.
	nc.Close()
	is.Eventually(func() bool {
		c, derr := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
		if derr == nil {
			c.Close()
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "pre-auth slot never released")
}

// TestServerMaxSessionsPerUser verifies the per-principal session cap across
// connections: one user cannot open more sessions than allowed, even over
// many connections.
func TestServerMaxSessionsPerUser(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{MaxSessionsPerUser: 1}})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	must.NoError(err, "first connection")
	defer c1.Close()

	// The first session holds the user's single slot.
	s1, err := c1.NewSession()
	must.NoError(err, "first session")
	defer s1.Close()

	// A second connection by the same user must be refused a session.
	c2, err := dial(t, addr, user, auth)
	must.NoError(err, "second connection")
	defer c2.Close()
	s2, err := c2.NewSession()
	if s2 != nil {
		s2.Close()
	}
	must.Error(err, "second session for the same user unexpectedly accepted")

	// Freeing the first session releases the user's slot.
	s1.Close()
	is.Eventually(func() bool {
		s3, serr := c2.NewSession()
		if serr == nil {
			s3.Close()
			return true
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "per-user session cap never released")
}

// TestServerClientAlive verifies an unresponsive client is disconnected after
// ClientAliveInterval*3 of silence, while a responsive one survives.
func TestServerClientAlive(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{Tunables: Tunables{ClientAliveInterval: 100 * time.Millisecond}},
	)
	defer closeFn()

	// A "responsive" client. Send a global request (e.g. keepalive) from time
	// to time so the server sees inbound traffic.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	defer client.Close()

	// Keep sending requests. Connection must stay alive well past the probe
	// window.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				_, _, _ = client.SendRequest("keepalive@openssh.com", true, nil)
			}
		}
	}()
	time.Sleep(700 * time.Millisecond)
	close(stop)

	// The session still works.
	sess, err := client.NewSession()
	must.NoError(err, "session after keepalives")
	defer sess.Close()
	out, err := sess.Output("echo alive")
	must.NoError(err)
	is.Equal("alive\n", string(out))
}

// TestServerClientAliveSilent verifies a client that stops responding is
// dropped.
func TestServerClientAliveSilent(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{Tunables: Tunables{ClientAliveInterval: 100 * time.Millisecond}},
	)
	defer closeFn()

	// Complete the handshake but never service global requests. The
	// server's keepalives go unanswered and the connection stays silent.
	nc, err := net.Dial("tcp", addr)
	must.NoError(err)
	defer nc.Close()

	cfg := &ssh.ClientConfig{
		User:            currentUser(t),
		Auth:            []ssh.AuthMethod{userCert(t, ca, testPrincipal)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	}
	conn, _, _, err := ssh.NewClientConn(nc, "tcp", cfg)
	must.NoError(err)

	// The server must close the connection once its keepalives stop getting
	// answered (ClientAliveInterval * 3). Wait() blocks until the connection
	// ends, so run it on a goroutine.
	done := make(chan error, 1)
	go func() { done <- conn.Wait() }()
	select {
	case err = <-done:
		t.Logf("connection closed by server: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not disconnect silent client")
	}
}
