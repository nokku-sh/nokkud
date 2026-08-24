package sshd

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
)

// agentRequest handles the client's auth-agent-req@openssh.com session
// request (ssh -A). When forwarding is allowed it is acknowledged and the
// session's SSH_AUTH_SOCK is wired to a Unix socket that relays connections
// to the client's agent over auth-agent@openssh.com channels. It reports
// whether the request was accepted (so the caller starts serveAgent).
func (sess *session) agentRequest(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}
	if !sess.server.tun.Load().AllowAgentForwarding {
		_ = req.Reply(false, nil)
		return false
	}
	if sess.agentLn != nil {
		_ = req.Reply(true, nil)
		return false
	}
	ln, sock, err := newAgentSock()
	if err != nil {
		sess.server.logger.Debug("sshd: agent socket", "error", err)
		_ = req.Reply(false, nil)
		return false
	}
	sess.agentLn = ln
	sess.agentSock = sock
	_ = req.Reply(true, nil)
	return true
}

// newAgentSock creates a temporary Unix socket and returns the listener and
// its path.
func newAgentSock() (net.Listener, string, error) {
	dir, err := os.MkdirTemp("", "auth-agent")
	if err != nil {
		return nil, "", err
	}
	sock := filepath.Join(dir, "listener.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, "", err
	}
	return ln, sock, nil
}

// serveAgent relays connections on the agent socket to the client's agent
// channel until the session ends. It runs for the lifetime of the session.
func (sess *session) serveAgent() {
	defer sess.server.recoverAndLog("agent forwarding", func() {
		_ = sess.agentLn.Close()
	})
	defer func() {
		_ = os.RemoveAll(filepath.Dir(sess.agentSock))
	}()

	// Stop accepting when the session ends.
	go func() {
		<-sess.ctx.Done()
		_ = sess.agentLn.Close()
	}()

	for {
		c, err := sess.agentLn.Accept()
		if err != nil {
			return
		}
		go sess.relayAgentConn(c)
	}
}

// relayAgentConn proxies one agent socket connection to a fresh
// auth-agent@openssh.com channel on the session's connection.
func (sess *session) relayAgentConn(c net.Conn) {
	defer sess.server.recoverAndLog("agent relay", func() { _ = c.Close() })
	ch, reqs, err := sess.conn.OpenChannel(agentChannelType, nil)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(c, ch)
		if u, ok := c.(*net.UnixConn); ok {
			_ = u.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(ch, c)
		_ = ch.CloseWrite()
	})
	wg.Wait()
}
