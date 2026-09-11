package sshd

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// aliveConn wraps a [net.Conn] so inbound traffic refreshes a read deadline,
// tearing down a client that sends nothing for the timeout window.
type aliveConn struct {
	net.Conn

	timeout time.Duration
	mu      sync.Mutex
	active  bool
}

func (c *aliveConn) activate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = true
	c.refreshLocked()
}

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

// clientAlive sends keepalive requests every interval. A client that stops
// answering is dropped when the read deadline passes (OpenSSH semantics).
func (s *Server) clientAlive(conn *ssh.ServerConn, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if _, _, err := conn.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				s.logger.Debug("client-alive failed",
					"remote", conn.RemoteAddr(), "error", err)
				_ = conn.Close()
				return
			}
		}
	}
}
