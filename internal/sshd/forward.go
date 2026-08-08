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

// directTCPIPData is the payload of a direct-tcpip channel open (RFC 4254
// section 7.2): the client asks the server to connect to dest and relay.
type directTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// connState tracks per-connection resources: the remote-forward listeners and
// the number of open session channels.
type connState struct {
	conn *ssh.ServerConn

	mu       sync.Mutex
	forwards map[string]net.Listener

	sessions atomic.Int32
}

func newConnState(conn *ssh.ServerConn) *connState {
	return &connState{conn: conn, forwards: make(map[string]net.Listener)}
}

// acquireSession counts a new session channel against the cap. A cap of zero
// means unlimited. Returns false without consuming a slot when over the cap.
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

// serveDirectTCPIP handles a direct-tcpip channel (-L/-D): connect to the
// requested destination and relay bytes both ways.
func (s *Server) serveDirectTCPIP(
	_ *Server,
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

	if !s.forwarding.Load() {
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

// handleGlobalRequests processes global requests for a connection:
// tcpip-forward / cancel-tcpip-forward (remote -R forwarding) and keepalives.
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

// tcpipForward binds a listener on the server for the client's -R request and
// starts accepting connections into forwarded-tcpip channels back to the
// client.
func (s *Server) tcpipForward(st *connState, req *ssh.Request) {
	if !s.forwarding.Load() {
		_ = req.Reply(false, []byte("port forwarding is disabled"))
		return
	}
	var f tcpipForwardData
	if err := ssh.Unmarshal(req.Payload, &f); err != nil {
		_ = req.Reply(false, nil)
		return
	}
	// The address the server binds is policy-controlled (loopback unless
	// gateway ports are enabled); the address reported back to the client in
	// the forwarded-tcpip channel is the one the client requested verbatim.
	// OpenSSH clients key their -R forward by the requested address, so
	// rewriting it (e.g. localhost -> 127.0.0.1) would make them reject the
	// channel.
	bindAddr := remoteBindAddr(f.BindAddr, s.gatewayPorts.Load())
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

// remoteBindAddr resolves the address a remote (-R) forward's listener binds,
// mirroring OpenSSH's GatewayPorts: unless gateway forwarding is enabled, the
// listener is forced onto the loopback address regardless of what the client
// requested, so an authorized user cannot expose a service on the server's
// external interfaces. With gateway forwarding enabled, an empty request binds
// all interfaces like OpenSSH does. The address reported back to the client is
// handled separately and is always the client's requested address.
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
		remoteBindAddr(f.BindAddr, s.gatewayPorts.Load()),
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

// acceptForwarded accepts connections on a remote-forward listener and sends
// each to the client as a forwarded-tcpip channel. destAddr is the address the
// client originally requested, reported back verbatim so the client can match
// the channel to its registered -R forward.
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

// proxyForward relays bytes between an SSH channel and a TCP connection in
// both directions until either side closes, then closes both.
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
