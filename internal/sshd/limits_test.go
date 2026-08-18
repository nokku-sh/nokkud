package sshd

import (
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestServerMaxConnections verifies the concurrent connection cap: an
// over-cap connection is refused immediately.
func TestServerMaxConnections(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{MaxConnections: 1})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer c1.Close()

	// A second connection while the first is live must be refused.
	if _, err = dial(t, addr, user, auth); err == nil {
		t.Fatal("second connection unexpectedly accepted")
	}

	// Closing the first frees a slot (server notices asynchronously).
	c1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var c2 *ssh.Client
		c2, err = dial(t, addr, user, auth)
		if err == nil {
			c2.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("connection cap never released")
}

// TestServerMaxStartups verifies the pre-auth connection cap: a half-open
// connection (never completing the handshake) holds a slot and a second
// connection is refused until it frees it.
func TestServerMaxStartups(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{MaxStartups: 1})
	defer closeFn()

	// A raw TCP connection that never completes the SSH handshake holds the
	// single pre-auth slot.
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close()
	// Give the server time to accept and take the slot.
	time.Sleep(100 * time.Millisecond)

	// A real SSH dial must be refused while the slot is held.
	if _, err = dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal)); err == nil {
		t.Fatal("dial succeeded while the pre-auth slot was held")
	}

	// Closing the half-open connection frees the slot.
	nc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
		if derr == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("pre-auth slot never released")
}

// TestServerMaxSessionsPerUser verifies the per-principal session cap across
// connections: one user cannot open more sessions than allowed, even over
// many connections.
func TestServerMaxSessionsPerUser(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{MaxSessionsPerUser: 1})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	c1, err := dial(t, addr, user, auth)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer c1.Close()

	// The first session holds the user's single slot.
	s1, err := c1.NewSession()
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	defer s1.Close()

	// A second connection by the same user must be refused a session.
	c2, err := dial(t, addr, user, auth)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer c2.Close()
	s2, err := c2.NewSession()
	if err == nil {
		s2.Close()
		t.Fatal("second session for the same user unexpectedly accepted")
	}

	// Freeing the first session releases the user's slot.
	s1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var s3 *ssh.Session
		s3, err = c2.NewSession()
		if err == nil {
			s3.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("per-user session cap never released")
}

// TestServerClientAlive verifies an unresponsive client is disconnected after
// ClientAliveInterval*3 of silence, while a responsive one survives.
func TestServerClientAlive(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{ClientAliveInterval: 100 * time.Millisecond},
	)
	defer closeFn()

	// A "responsive" client. Send a global request (e.g. keepalive) from time
	// to time so the server sees inbound traffic.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
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
	if err != nil {
		t.Fatalf("session after keepalives: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo alive")
	if err != nil || string(out) != "alive\n" {
		t.Fatalf("exec after keepalives: %q err=%v", out, err)
	}
}

// TestServerClientAliveSilent verifies a client that stops responding is
// dropped.
func TestServerClientAliveSilent(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(
		t,
		ca,
		Options{ClientAliveInterval: 100 * time.Millisecond},
	)
	defer closeFn()

	// Complete the handshake but never service global requests. The
	// server's keepalives go unanswered and the connection stays silent.
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close()

	cfg := &ssh.ClientConfig{
		User:            currentUser(t),
		Auth:            []ssh.AuthMethod{userCert(t, ca, testPrincipal)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
		Timeout:         10 * time.Second,
	}
	conn, _, _, err := ssh.NewClientConn(nc, "tcp", cfg)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

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
