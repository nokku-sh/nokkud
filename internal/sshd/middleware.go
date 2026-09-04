package sshd

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

// channelHandler serves one channel of a given type. It owns accepting the
// channel and returns it, or nil when it rejected the open, so outer
// middlewares can clean it up.
type channelHandler func(*Server, *ssh.ServerConn, *connState, ssh.NewChannel) ssh.Channel

// channelMiddleware wraps a channelHandler. In use, the first middleware is
// outermost, so the stack reads left to right in execution order.
type channelMiddleware func(channelHandler) channelHandler

// use composes middlewares around h.
func use(h channelHandler, mw ...channelMiddleware) channelHandler {
	for _, m := range slices.Backward(mw) {
		h = m(h)
	}
	return h
}

// channelHandlers maps SSH channel types to handler stacks so new types and
// features slot in without touching the accept loop.
var channelHandlers = map[string]channelHandler{
	"session":      use(serveSessionChannel, recoverChannel, sessionCaps),
	"direct-tcpip": use(serveDirectTCPIP, recoverChannel),
}

// recoverChannel contains panics from the handler below it so a single
// session cannot take the daemon down. It closes the accepted channel, or
// rejects the pending open when the handler died before accepting.
func recoverChannel(next channelHandler) channelHandler {
	return func(s *Server, conn *ssh.ServerConn, st *connState, newCh ssh.NewChannel) ssh.Channel {
		var ch ssh.Channel
		defer s.recoverAndLog("channel "+newCh.ChannelType(), func() {
			if ch != nil {
				_ = ch.Close()
				return
			}
			_ = newCh.Reject(ssh.ConnectionFailed, "channel handler failed")
		})
		ch = next(s, conn, st, newCh)
		return ch
	}
}

// sessionCaps enforces the per-connection and per-principal session caps
// before the session channel is accepted.
func sessionCaps(next channelHandler) channelHandler {
	return func(s *Server, conn *ssh.ServerConn, st *connState, newCh ssh.NewChannel) ssh.Channel {
		if !st.acquireSession(s.tun.Load().MaxSessions) {
			_ = newCh.Reject(ssh.ResourceShortage, "too many sessions")
			return nil
		}
		defer st.releaseSession()

		if !s.acquirePrincipalSession(conn.User(), s.tun.Load().MaxSessionsPerUser) {
			_ = newCh.Reject(ssh.ResourceShortage, "too many sessions for user")
			return nil
		}
		defer s.releasePrincipalSession(conn.User())

		return next(s, conn, st, newCh)
	}
}
