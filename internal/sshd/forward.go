package sshd

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// directTCPIPData is the payload of a direct-tcpip channel open
// (RFC 4254 section 7.2).
type directTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// connState tracks per-connection resources and the open session count.
type connState struct {
	conn *ssh.ServerConn

	mu       sync.Mutex
	forwards map[string]net.Listener

	sessions atomic.Int32
}

func newConnState(conn *ssh.ServerConn) *connState {
	return &connState{conn: conn, forwards: make(map[string]net.Listener)}
}

// acquireSession counts a session channel against the cap. Zero means
// unlimited. Returns false without consuming a slot when over the cap.
func (st *connState) acquireSession(limit int) bool {
	if limit <= 0 {
		return true
	}
	for {
		n := st.sessions.Load()
		if int64(n) >= int64(limit) {
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

// close stops all remote-forward listeners when the connection ends.
func (st *connState) close() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, ln := range st.forwards {
		_ = ln.Close()
	}
	st.forwards = nil
}

// serveDirectTCPIP handles a direct-tcpip channel (-L/-D) by relaying
// bytes between the client and the requested destination.
func (s *Server) serveDirectTCPIP(
	_ *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
	ch *ssh.Channel,
) {
	var d directTCPIPData
	if err := ssh.Unmarshal(newCh.ExtraData(), &d); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}

	if !s.tun.Load().forwarding {
		_ = newCh.Reject(ssh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatUint(uint64(d.DestPort), 10))
	var dialer net.Dialer
	dconn, err := dialer.DialContext(context.Background(), "tcp", dest)
	if err != nil {
		s.logger.Debug("sshd: direct-tcpip dial", "dest", dest, "error", err)
		_ = newCh.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	ev := eventWith(connEvent(st.conn), audit.EventForward, "", "")
	ev.Target = dest
	s.emit(ev)

	c, reqs, err := newCh.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	*ch = c
	go ssh.DiscardRequests(reqs)

	go proxyForward(s, c, dconn)
}

// handleGlobalRequests processes global requests, meaning remote -R
// forwarding and keepalives.
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

type tcpipForwardData struct {
	BindAddr string
	BindPort uint32
}

type tcpipForwardSuccess struct {
	BindPort uint32
}

// tcpipForward binds a listener for the client's -R request and accepts
// connections into forwarded-tcpip channels back to the client.
func (s *Server) tcpipForward(st *connState, req *ssh.Request) {
	if !s.tun.Load().forwarding {
		_ = req.Reply(false, []byte("port forwarding is disabled"))
		return
	}
	var f tcpipForwardData
	if err := ssh.Unmarshal(req.Payload, &f); err != nil {
		_ = req.Reply(false, nil)
		return
	}
	// Bind policy-controlled. Loopback unless gateway ports are enabled.
	// The address reported back to the client is the one requested verbatim,
	// since OpenSSH keys -R forwards by it.
	bindAddr := remoteBindAddr(f.BindAddr, s.tun.Load().gatewayPorts)
	addr := net.JoinHostPort(bindAddr, strconv.FormatUint(uint64(f.BindPort), 10))

	st.mu.Lock()
	_, exists := st.forwards[addr]
	if !exists {
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err == nil {
			st.forwards[addr] = ln
			go s.acceptForwarded(st, ln, f.BindAddr)
		}
	}
	st.mu.Unlock()
	if exists {
		_ = req.Reply(false, nil)
		return
	}

	st.mu.Lock()
	ln := st.forwards[addr]
	st.mu.Unlock()
	if ln == nil {
		_ = req.Reply(false, nil)
		return
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.ParseUint(portStr, 10, 32)
	_ = req.Reply(true, ssh.Marshal(tcpipForwardSuccess{BindPort: uint32(port)}))
}

// remoteBindAddr mirrors OpenSSH's GatewayPorts. Unless enabled, force the
// listener onto loopback so a user cannot expose a service on the server's
// external interfaces. With it enabled, an empty request binds all
// interfaces. The address reported to the client is always the requested one.
func remoteBindAddr(requested string, gateway bool) string {
	if !gateway {
		return "127.0.0.1"
	}
	if requested == "" {
		return "0.0.0.0"
	}
	return requested
}

// cancelTCPIPForward closes a previously bound remote-forward listener.
func (s *Server) cancelTCPIPForward(st *connState, req *ssh.Request) {
	var f tcpipForwardData
	if err := ssh.Unmarshal(req.Payload, &f); err != nil {
		_ = req.Reply(false, nil)
		return
	}
	addr := net.JoinHostPort(
		remoteBindAddr(f.BindAddr, s.tun.Load().gatewayPorts),
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

type forwardedTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// acceptForwarded sends listener connections to the client as
// forwarded-tcpip channels. destAddr is the requested address, reported
// verbatim so the client can match its registered -R forward.
func (s *Server) acceptForwarded(st *connState, ln net.Listener, destAddr string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer s.recoverAndLog("forwarded-tcpip accept", func() { _ = c.Close() })
			originAddr, originPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			originPort, _ := strconv.ParseUint(originPortStr, 10, 32)
			payload := ssh.Marshal(forwardedTCPIPData{
				DestAddr:   destAddr,
				DestPort:   portOfListener(ln),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})
			ch, reqs, openErr := st.conn.OpenChannel("forwarded-tcpip", payload)
			if openErr != nil {
				s.logger.Debug("sshd: open forwarded-tcpip channel", "error", openErr)
				return
			}
			go ssh.DiscardRequests(reqs)
			proxyForward(s, ch, c)
		}()
	}
}

// proxyForward relays bytes between an SSH channel and a TCP connection
// until either side closes, then closes both.
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

// portOfListener extracts the actual bound port of a listener.
func portOfListener(ln net.Listener) uint32 {
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.ParseUint(portStr, 10, 32)
	return uint32(port)
}
