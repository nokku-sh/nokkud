package sshd

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// aliveConn wraps a [net.Conn] so that inbound traffic (including replies to
// keepalives) refreshes a read deadline. A client that sends nothing for the
// timeout window stops the underlying reads and tears the connection down.
type aliveConn struct {
	net.Conn

	timeout time.Duration
	mu      sync.Mutex
	active  bool
}

// activate arms the read deadline after the handshake completes.
func (c *aliveConn) activate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = true
	c.refreshLocked()
}

// Read refreshes the deadline on any inbound traffic.
func (c *aliveConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.active {
		c.refreshLocked()
	}
	c.mu.Unlock()

	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if c.active {
			c.refreshLocked()
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *aliveConn) refreshLocked() {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
}

// clientAlive sends keepalive global requests every interval. A healthy
// client answers, refreshing the read deadline; a client that stops
// responding is dropped once the deadline passes (OpenSSH's
// ClientAliveInterval + ClientAliveCountMax=3).
func (s *Server) clientAlive(conn *ssh.ServerConn, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				s.logger.Debug(
					"sshd: client-alive failed",
					"remote",
					conn.RemoteAddr(),
					"error",
					err,
				)
				_ = conn.Close()
				return
			}
		}
	}
}
