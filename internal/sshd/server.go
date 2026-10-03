// Package sshd implements the embedded SSH server.
package sshd

import (
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokkud/internal/sysutil"
)

const (
	maxConns    = 100
	maxStartups = 10
	// maxSourceStartups caps one remote address, so a single peer cannot hold
	// every pre-auth slot.
	maxSourceStartups = 3
	// maxChannels caps the channels one connection holds open, sessions and
	// forwards alike.
	maxChannels      = 50
	handshakeTimeout = 10 * time.Second
	// aliveInterval is how often an idle client is probed. A probe left
	// unanswered for three intervals drops the client, like OpenSSH.
	aliveInterval = time.Minute
	// acceptBackoff bounds the accept retry delay under fd exhaustion, so the
	// loop does not spin a core and flood the log.
	acceptBackoff = 10 * time.Millisecond
)

var errBusy = errors.New("too many unauthenticated connections")

// Policy is the backend-controlled part of the server config. It applies to
// new sessions without a restart.
type Policy struct {
	Record               bool
	AllowForwarding      bool
	AllowAgentForwarding bool
	// GatewayPorts lets -R forwards bind non-loopback addresses.
	GatewayPorts bool
	// DropRetiredCA stops trusting a rotated-out CA before its grace ends.
	DropRetiredCA bool
}

// DefaultPolicy applies until the backend sends a config, and to any field
// the backend leaves unset.
var DefaultPolicy = Policy{Record: true, AllowForwarding: true, AllowAgentForwarding: true}

// RecordingSink opens the upload stream for one session's recording. The ctx
// outlives the session teardown.
type RecordingSink func(ctx context.Context, sessionID, username string) io.WriteCloser

type Options struct {
	// Principals returns the subject UUIDs allowed to log in as username.
	Principals func(username string) []string
	// Log gets the audit events. Nil means the default logger.
	Log           *slog.Logger
	Policy        Policy
	RecordingSink RecordingSink
	// TrustedCAs seeds the CA set until Reload reads it from disk. Tests only.
	TrustedCAs []ssh.PublicKey
	// NologinFile defaults to /etc/nologin. Tests only.
	NologinFile string
}

type Server struct {
	principals    func(username string) []string
	log           *slog.Logger
	recordingSink RecordingSink
	nologinFile   string
	policy        atomic.Pointer[Policy]

	// Limits live on the server so tests can shrink them.
	conns chan struct{}
	// Loopback has its own pre-auth budget. Relayed connections arrive from
	// there and a network peer must not starve them.
	startups      chan struct{}
	localStartups chan struct{}
	maxChannels   int
	aliveInterval time.Duration

	startupMu      sync.Mutex
	sourceStartups map[netip.Addr]int

	liveMu sync.Mutex
	live   map[*ssh.ServerConn]struct{}

	// The host key stays open as long as the server runs. A connection signs
	// with it again on every rekey, long after its handshake.
	hostKey    ssh.Signer
	hostKeyDev io.Closer

	mu         sync.RWMutex
	cfg        *ssh.ServerConfig
	trustedCAs map[string]struct{}
}

// New loads the host key and trusted CAs. A missing CA file is fine on first
// boot, the first sync writes it and Reload picks it up.
func New(opts Options) (*Server, error) {
	if opts.Principals == nil {
		return nil, errors.New("sshd: Principals is required")
	}
	s := &Server{
		principals:     opts.Principals,
		log:            cmp.Or(opts.Log, slog.Default()),
		recordingSink:  opts.RecordingSink,
		nologinFile:    opts.NologinFile,
		conns:          make(chan struct{}, maxConns),
		startups:       make(chan struct{}, maxStartups),
		localStartups:  make(chan struct{}, maxStartups),
		sourceStartups: map[netip.Addr]int{},
		live:           map[*ssh.ServerConn]struct{}{},
		maxChannels:    maxChannels,
		aliveInterval:  aliveInterval,
		trustedCAs:     caKeys(opts.TrustedCAs),
	}
	if s.nologinFile == "" {
		s.nologinFile = sysutil.NologinFile
	}
	s.policy.Store(&opts.Policy)
	var err error
	if s.hostKey, s.hostKeyDev, err = loadHostKey(); err != nil {
		return nil, err
	}
	s.Reload()
	return s, nil
}

// PolicyFrom overlays a synced daemon config on DefaultPolicy. Fields the
// backend never set keep the default.
func PolicyFrom(cfg *nokkuv1.DaemonConfig) Policy {
	p := DefaultPolicy
	if cfg == nil {
		return p
	}
	// The raw pointers carry presence, the getters would flatten unset to
	// false.
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	set(&p.Record, cfg.RecordSessions)                     //nolint:protogetter // presence check
	set(&p.AllowForwarding, cfg.AllowForwarding)           //nolint:protogetter // presence check
	set(&p.AllowAgentForwarding, cfg.AllowAgentForwarding) //nolint:protogetter // presence check
	set(&p.GatewayPorts, cfg.GatewayPorts)                 //nolint:protogetter // presence check
	set(&p.DropRetiredCA, cfg.DropRetiredCa)               //nolint:protogetter // presence check
	return p
}

func (s *Server) SetPolicy(p Policy) {
	old := s.policy.Swap(&p)
	if old.DropRetiredCA != p.DropRetiredCA {
		s.Reload()
	}
}

// Reload rereads the trusted CAs and the host certificate. Established
// connections keep the certificate they handshook with.
func (s *Server) Reload() {
	trusted, caErr := loadTrustedCAs(s.policy.Load().DropRetiredCA)
	switch {
	case errors.Is(caErr, fs.ErrNotExist):
		slog.Debug("trusted CAs not synced yet")
	case caErr != nil:
		// Keep the last good set: a bad line must not lock everyone out.
		slog.Warn("reload trusted CAs failed, keeping previous set", "error", caErr)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback:         s.publicKeyCallback,
		VerifiedPublicKeyCallback: s.verifiedPublicKey,
		BannerCallback:            s.banner,
		ServerVersion:             "SSH-2.0-nokkud",
	}
	cfg.AddHostKey(withHostCert(s.hostKey))

	s.mu.Lock()
	defer s.mu.Unlock()
	if caErr == nil {
		s.trustedCAs = caKeys(trusted)
	}
	s.cfg = cfg
}

// Serve accepts connections on l until ctx is done or l is closed, then
// releases the host key. Established sessions are left to die
// with the process.
func (s *Server) Serve(ctx context.Context, l net.Listener) {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	defer s.hostKeyDev.Close()

	var delay time.Duration
	for {
		nc, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			delay = min(2*delay+acceptBackoff, time.Second)
			slog.Error("accept failed", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		select {
		case s.conns <- struct{}{}:
		default:
			slog.Warn("dropping connection, at capacity", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		go func() {
			defer func() { <-s.conns }()
			s.handleConn(nc)
		}()
	}
}

// DropRevoked closes every open connection whose principal lost access to
// its account. The principals only gate new logins, so a sync calls this to
// make a revoke end the sessions that are already open.
func (s *Server) DropRevoked() {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	for conn := range s.live {
		if slices.Contains(s.principals(conn.User()), conn.Permissions.Extensions["nokku-principal"]) {
			continue
		}
		slog.Info("closing connection, access was revoked", "user", conn.User(), "remote", conn.RemoteAddr())
		_ = conn.Close()
	}
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	defer recoverPanic("connection")

	conn, chans, reqs, err := s.handshake(nc)
	if errors.Is(err, errBusy) {
		slog.Warn("dropping connection", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	if err != nil {
		slog.Debug("handshake failed", "remote", nc.RemoteAddr(), "error", err)
		return
	}
	defer conn.Close()
	s.liveMu.Lock()
	s.live[conn] = struct{}{}
	s.liveMu.Unlock()
	defer func() {
		s.liveMu.Lock()
		delete(s.live, conn)
		s.liveMu.Unlock()
	}()
	slog.Info("connection established",
		"user", conn.User(), "remote", conn.RemoteAddr(), "client", string(conn.ClientVersion()))

	st := newConnState(conn, s.maxChannels)
	defer st.close()
	done := make(chan struct{})
	defer close(done)
	go s.keepAlive(conn, done)
	go s.handleGlobalRequests(st, reqs)

	var wg sync.WaitGroup
	defer wg.Wait()
	for newCh := range chans {
		var serve func(*connState, ssh.NewChannel)
		switch newCh.ChannelType() {
		case "session":
			serve = s.serveSession
		case "direct-tcpip":
			serve = s.serveDirectTCPIP
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if !st.acquireChannel() {
			_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}
		wg.Go(func() {
			defer st.releaseChannel()
			defer recoverPanic(newCh.ChannelType())
			serve(st, newCh)
		})
	}
}

// handshake holds a pre-auth slot only while the handshake runs, and bounds a
// peer that never finishes it.
func (s *Server) handshake(nc net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	release, ok := s.acquireStartup(nc.RemoteAddr())
	if !ok {
		return nil, nil, nil, errBusy
	}
	defer release()
	if err := nc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, nil, nil, err
	}
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return conn, chans, reqs, nc.SetDeadline(time.Time{})
}

// acquireStartup takes a pre-auth slot for addr. IPv6 peers count per /64.
func (s *Server) acquireStartup(addr net.Addr) (release func(), ok bool) {
	var source netip.Addr
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		source = ap.Addr().Unmap()
	}
	if source.IsLoopback() {
		select {
		case s.localStartups <- struct{}{}:
			return func() { <-s.localStartups }, true
		default:
			return nil, false
		}
	}
	if source.Is6() {
		source = netip.PrefixFrom(source, 64).Masked().Addr()
	}

	s.startupMu.Lock()
	defer s.startupMu.Unlock()
	if s.sourceStartups[source] >= maxSourceStartups {
		return nil, false
	}
	select {
	case s.startups <- struct{}{}:
	default:
		return nil, false
	}
	s.sourceStartups[source]++
	return func() {
		<-s.startups
		s.startupMu.Lock()
		defer s.startupMu.Unlock()
		if s.sourceStartups[source]--; s.sourceStartups[source] == 0 {
			delete(s.sourceStartups, source)
		}
	}, true
}

func (s *Server) keepAlive(conn *ssh.ServerConn, done <-chan struct{}) {
	t := time.NewTicker(s.aliveInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		kill := time.AfterFunc(3*s.aliveInterval, func() { _ = conn.Close() })
		_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
		kill.Stop()
		if err != nil {
			return
		}
	}
}

// banner tells the client before auth that the session is recorded.
func (s *Server) banner(ssh.ConnMetadata) string {
	if !s.policy.Load().Record {
		return ""
	}
	return "This session is recorded and audited.\r\n"
}

// recoverPanic keeps one bad connection or channel from killing the daemon.
// Deferred cleanup in the caller still runs.
func recoverPanic(where string) {
	if r := recover(); r != nil {
		slog.Error("recovered panic", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
}
