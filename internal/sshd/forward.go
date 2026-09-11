package sshd

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// tcpipChannelData is the payload of a direct-tcpip (RFC 4254 7.2) or
// forwarded-tcpip (7.3) channel open. Both share this layout.
type tcpipChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type tcpipForwardData struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardSuccess struct {
	BindPort uint32
}

// connState tracks per-connection resources and the open session count.
type connState struct {
	conn *ssh.ServerConn

	mu       sync.Mutex
	forwards map[string]net.Listener

	sessions atomic.Int64
	channels atomic.Int64
}

func newConnState(conn *ssh.ServerConn) *connState {
	return &connState{conn: conn, forwards: make(map[string]net.Listener)}
}

// acquireSession counts a session against the cap. Zero means unlimited, and
// an over-cap call returns false without consuming a slot.
func (st *connState) acquireSession(limit int) bool {
	if limit <= 0 {
		return true
	}
	for {
		n := st.sessions.Load()
		if n >= int64(limit) {
			return false
		}
		if st.sessions.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (st *connState) releaseSession() {
	st.sessions.Add(-1)
}

// acquireChannel counts an open channel against the cap. Zero means unlimited,
// and an over-cap call returns false without consuming a slot.
func (st *connState) acquireChannel(limit int) bool {
	if limit <= 0 {
		return true
	}
	for {
		n := st.channels.Load()
		if n >= int64(limit) {
			return false
		}
		if st.channels.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (st *connState) releaseChannel() {
	st.channels.Add(-1)
}

func (st *connState) close() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, ln := range st.forwards {
		_ = ln.Close()
	}
	st.forwards = nil
}

// serveDirectTCPIP serves a direct-tcpip channel (-L/-D), relaying bytes
// between the client and the requested destination.
func serveDirectTCPIP(
	s *Server,
	conn *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
) ssh.Channel {
	var d tcpipChannelData
	if err := ssh.Unmarshal(newCh.ExtraData(), &d); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return nil
	}

	if !s.tun.Load().AllowForwarding || !certExt(conn, "permit-port-forwarding") {
		_ = newCh.Reject(ssh.Prohibited, "port forwarding is disabled")
		return nil
	}
	// Hold the channel slot for the relay, not just for the open request.
	if !st.acquireChannel(s.tun.Load().MaxChannels) {
		_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
		return nil
	}
	defer st.releaseChannel()

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatUint(uint64(d.DestPort), 10))
	// A black-holed destination must not hang the channel open forever.
	dialer := net.Dialer{Timeout: 5 * time.Second}
	dconn, err := dialer.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		s.logger.Debug("direct-tcpip dial failed", "addr", dest, "error", err)
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return nil
	}

	ev := eventWith(connEvent(st.conn), audit.EventForward, "", "")
	ev.Target = dest
	s.emit(ev)

	c, reqs, err := newCh.Accept()
	if err != nil {
		_ = dconn.Close()
		return nil
	}
	go ssh.DiscardRequests(reqs)

	proxyForward(s, c, dconn)
	return c
}

func (s *Server) handleGlobalRequests(_ *ssh.ServerConn, st *connState, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			s.tcpipForward(st, req)
		case "cancel-tcpip-forward":
			s.cancelTCPIPForward(st, req)
		case "keepalive@openssh.com":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// tcpipForward binds the listener for a client -R request and accepts
// connections into forwarded-tcpip channels back to the client.
func (s *Server) tcpipForward(st *connState, req *ssh.Request) {
	if !s.tun.Load().AllowForwarding || !certExt(st.conn, "permit-port-forwarding") {
		_ = req.Reply(false, []byte("port forwarding is disabled"))
		return
	}
	var f tcpipForwardData
	if err := ssh.Unmarshal(req.Payload, &f); err != nil {
		_ = req.Reply(false, nil)
		return
	}
	// Bind policy-controlled: loopback unless gateway ports are enabled.
	// OpenSSH keys -R forwards by the verbatim requested address.
	bindAddr := remoteBindAddr(f.BindAddr, s.tun.Load().GatewayPorts)
	addr := net.JoinHostPort(bindAddr, strconv.FormatUint(uint64(f.BindPort), 10))

	st.mu.Lock()
	_, exists := st.forwards[addr]
	if !exists {
		var lc net.ListenConfig
		if ln, err := lc.Listen(context.Background(), "tcp", addr); err == nil {
			st.forwards[addr] = ln
			go s.acceptForwarded(st, ln, f.BindAddr)
			st.mu.Unlock()
			_ = req.Reply(true, ssh.Marshal(tcpipForwardSuccess{BindPort: portOfListener(ln)}))
			return
		}
	}
	st.mu.Unlock()
	_ = req.Reply(false, nil)
}

// remoteBindAddr pins the listener to loopback unless OpenSSH's GatewayPorts
// is enabled, so a user cannot expose a service on the server's interfaces.
func remoteBindAddr(requested string, gateway bool) string {
	if !gateway {
		return "127.0.0.1"
	}
	if requested == "" {
		return "0.0.0.0"
	}
	return requested
}

func (s *Server) cancelTCPIPForward(st *connState, req *ssh.Request) {
	var f tcpipForwardData
	if err := ssh.Unmarshal(req.Payload, &f); err != nil {
		_ = req.Reply(false, nil)
		return
	}
	addr := net.JoinHostPort(
		remoteBindAddr(f.BindAddr, s.tun.Load().GatewayPorts),
		strconv.FormatUint(uint64(f.BindPort), 10),
	)

	st.mu.Lock()
	ln, ok := st.forwards[addr]
	if ok {
		delete(st.forwards, addr)
		_ = ln.Close()
	}
	st.mu.Unlock()
	_ = req.Reply(ok, nil)
}

// acceptForwarded sends listener connections to the client as forwarded-tcpip
// channels, reporting destAddr verbatim so the client matches its -R forward.
func (s *Server) acceptForwarded(st *connState, ln net.Listener, destAddr string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer s.recoverAndLog("forwarded-tcpip accept", func() { _ = c.Close() })
			if !st.acquireChannel(s.tun.Load().MaxChannels) {
				_ = c.Close()
				return
			}
			defer st.releaseChannel()
			originAddr, originPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			originPort, _ := strconv.ParseUint(originPortStr, 10, 32)
			payload := ssh.Marshal(tcpipChannelData{
				DestAddr:   destAddr,
				DestPort:   portOfListener(ln),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})
			ch, reqs, openErr := st.conn.OpenChannel("forwarded-tcpip", payload)
			if openErr != nil {
				s.logger.Debug("open forwarded-tcpip channel failed", "error", openErr)
				return
			}
			go ssh.DiscardRequests(reqs)
			proxyForward(s, ch, c)
		}()
	}
}

func proxyForward(s *Server, ch ssh.Channel, c net.Conn) {
	var wg sync.WaitGroup
	done := make(chan struct{})
	closeBoth := func() {
		select {
		case <-done:
		default:
			close(done)
			_ = ch.Close()
			_ = c.Close()
		}
	}

	wg.Go(func() {
		defer s.recoverAndLog("forward relay", closeBoth)
		_, _ = io.Copy(ch, c)
		closeBoth()
	})
	wg.Go(func() {
		defer s.recoverAndLog("forward relay", closeBoth)
		_, _ = io.Copy(c, ch)
		closeBoth()
	})
	wg.Wait()
}

func portOfListener(ln net.Listener) uint32 {
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.ParseUint(portStr, 10, 32)
	return uint32(port)
}
