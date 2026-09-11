package sshd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
)

// agentRequest handles the client's auth-agent-req@openssh.com request
// (ssh -A), wiring the session's agent socket to the client's agent.
func (sess *session) agentRequest(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}
	if !sess.server.tun.Load().AllowAgentForwarding || !certExt(sess.conn, "permit-agent-forwarding") {
		_ = req.Reply(false, nil)
		return false
	}
	if sess.agentLn != nil {
		_ = req.Reply(true, nil)
		return false
	}
	ln, sock, err := newAgentSock(sess.sysUser)
	if err != nil {
		sess.server.logger.Debug("create agent socket", "error", err)
		_ = req.Reply(false, nil)
		return false
	}
	sess.agentLn = ln
	sess.agentSock = sock
	_ = req.Reply(true, nil)
	return true
}

// newAgentSock creates a Unix socket owned by the target user. MkdirTemp
// leaves a root-owned dir the dropped-privilege session cannot traverse.
func newAgentSock(sysUser *user.User) (net.Listener, string, error) {
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

	if os.Geteuid() == 0 {
		uid, gid, idErr := userIDs(sysUser)
		if idErr != nil {
			_ = ln.Close()
			_ = os.RemoveAll(dir)
			return nil, "", idErr
		}
		for _, path := range []string{dir, sock} {
			if err = os.Chown(path, uid, gid); err != nil {
				_ = ln.Close()
				_ = os.RemoveAll(dir)
				return nil, "", fmt.Errorf("chown agent socket: %w", err)
			}
		}
		// Only the session user may talk to the forwarded agent.
		if err = os.Chmod(sock, 0o600); err != nil {
			_ = ln.Close()
			_ = os.RemoveAll(dir)
			return nil, "", fmt.Errorf("chmod agent socket: %w", err)
		}
	}
	return ln, sock, nil
}

func userIDs(u *user.User) (int, int, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}
	return uid, gid, nil
}

// serveAgent relays agent socket connections to the client's agent channel for
// the lifetime of the session.
func (sess *session) serveAgent() {
	defer sess.server.recoverAndLog("agent forwarding", func() {
		_ = sess.agentLn.Close()
	})
	defer func() {
		_ = os.RemoveAll(filepath.Dir(sess.agentSock))
	}()

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

func (sess *session) relayAgentConn(c net.Conn) {
	defer sess.server.recoverAndLog("agent relay", func() { _ = c.Close() })
	if !sess.st.acquireChannel(sess.server.tun.Load().MaxChannels) {
		_ = c.Close()
		return
	}
	defer sess.st.releaseChannel()
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
