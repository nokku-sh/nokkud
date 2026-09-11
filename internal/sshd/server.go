// Package sshd implements the embedded SSH server.
package sshd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// PrincipalsFunc reports the subject UUIDs allowed to log in as username. An
// empty result denies access.
type PrincipalsFunc func(username string) []string

// Audit is the event sink for security events. Safe for concurrent use.
type Audit interface {
	Emit(event audit.Event)
}

// shutdownGrace bounds how long Shutdown waits for active connections to drain
// before closing resources regardless. Deliberately not a context parameter.
const shutdownGrace = 10 * time.Second

// acceptBackoff bounds the accept retry delay on a live listener (EMFILE under
// fd exhaustion). Without it the loop spins a core and floods the log.
const acceptBackoff = 10 * time.Millisecond

// Server is an SSH server. Construct with New and serve with Serve.
type Server struct {
	logger      *slog.Logger
	cfg         *ssh.ServerConfig
	principals  PrincipalsFunc
	revoked     func(principal string) (int64, bool)
	audit       Audit
	nologinFile string

	// tun is swapped atomically so a concurrent SetTunables takes effect
	// without tearing down established connections.
	tun atomic.Pointer[Tunables]
	// defaults are the tunables the server was constructed with, which the
	// client overlays a synced backend config on. Never mutated after New.
	defaults Tunables

	// certsMu guards trustedCAs, hostKeys and cfg so a reload can swap them
	// without tearing down established connections.
	certsMu sync.RWMutex
	// trustedCAs holds the marshalled CA public keys so auth is a map lookup.
	trustedCAs map[string]struct{}
	hostKeys   []ssh.Signer
	// hostKeyClosers release the swapped-out identity's resources (e.g. TPM handles).
	hostKeyClosers []io.Closer

	activeConns     atomic.Int64
	unauthenticated atomic.Int64
	closeOnce       sync.Once
	connsWg         sync.WaitGroup

	// principalSessions counts active sessions per principal (SSH username) so
	// one user cannot exhaust the daemon across many connections.
	principalMu       sync.Mutex
	principalSessions map[string]int

	// limiters is a bounded per-source-IP cache of connection rate limiters.
	// Rate and burst come from the live tunables.
	limiters *lru.Cache[string, *rate.Limiter]

	// mu guards the listener installed by ListenAndServe so Close can stop it.
	mu       sync.Mutex
	listener net.Listener

	// recordingSinkFactory builds the upload sink for a session's recorder.
	// Nil disables uploading. The ctx must outlive the session teardown.
	recordingSinkFactory func(ctx context.Context, sessionID, username string) io.WriteCloser
}

// Tunables is the live-adjustable subset of the server policy. A concurrent
// SetTunables swaps them without touching established connections.
type Tunables struct {
	// Record enables session recording.
	Record bool
	// AllowForwarding enables port forwarding (-L/-D and -R).
	AllowForwarding bool
	// AllowAgentForwarding enables ssh-agent forwarding (SSH_AUTH_SOCK).
	AllowAgentForwarding bool
	// GatewayPorts allows remote (-R) forwards to bind non-loopback addresses.
	// Like OpenSSH GatewayPorts=no, the default pins them to 127.0.0.1.
	GatewayPorts bool
	// MaxSessions caps session channels per connection (OpenSSH MaxSessions).
	// Zero means no cap.
	MaxSessions int
	// MaxChannels caps channels a single connection may hold open across all
	// types. Zero means no cap.
	MaxChannels int
	// DropRetiredCA stops trusting a rotated-out CA immediately.
	DropRetiredCA bool
	// MaxConnections caps concurrent SSH connections. Zero means no cap.
	// Over-cap connections are dropped immediately.
	MaxConnections int
	// MaxStartups caps concurrent pre-auth handshake connections (OpenSSH
	// MaxStartups). Zero means no cap. Bounds brute-force and half-open floods.
	MaxStartups int
	// MaxSessionsPerUser caps concurrent sessions per authenticated principal
	// across all connections. Zero means no per-user cap.
	MaxSessionsPerUser int
	// ClientAliveInterval is how often the server probes an idle client, which
	// is dropped after 3 missed intervals (OpenSSH ClientAliveInterval). Zero
	// disables probing.
	ClientAliveInterval time.Duration
	// ConnRate caps new connections per second per source IP. Zero disables
	// rate limiting.
	ConnRate int
	// ConnRateBurst allows short bursts above ConnRate.
	ConnRateBurst int
	// Banner enables the pre-auth banner.
	Banner bool
}

type Options struct {
	Logger     *slog.Logger
	Principals PrincipalsFunc
	// RevokedBefore reports a principal's revocation cutoff. Certificates whose
	// ValidAfter is earlier than the cutoff are refused.
	RevokedBefore func(principal string) (int64, bool)
	Audit         Audit
	// TrustedCAs lists the CA public keys that may sign user certificates. When
	// empty, they are loaded from Paths.UserCAFile().
	TrustedCAs []ssh.PublicKey
	// NologinFile is the maintenance lockout file. Defaults to
	// sysutil.NologinFile (/etc/nologin).
	NologinFile string
	// Tunables is the compiled-in live-adjustable policy.
	Tunables Tunables
}

// SetRecordingSinkFactory installs the factory used to create per-session
// recording upload sinks. Set once by the client at startup.
func (s *Server) SetRecordingSinkFactory(
	fn func(ctx context.Context, sessionID, username string) io.WriteCloser,
) {
	s.recordingSinkFactory = fn
}

// DefaultTunables returns the compiled-in tunables the server was constructed
// with. The client overlays the backend's synced daemon config on top of these.
func (s *Server) DefaultTunables() Tunables {
	return s.defaults
}

// OptionsFrom returns the daemon's compiled-in SSH server policy, backed by the
// shared cache with the local audit sink. record enables session recording.
func OptionsFrom(cache *state.Cache, record bool) Options {
	return Options{
		Principals: func(username string) []string {
			return cache.GetUUIDs(username)
		},
		RevokedBefore: cache.RevokedBefore,
		Tunables: Tunables{
			Record:               record,
			AllowForwarding:      true,
			AllowAgentForwarding: true,
			MaxSessions:          10,
			MaxChannels:          50,
			MaxConnections:       100,
			MaxStartups:          10,
			ClientAliveInterval:  60 * time.Second,
			ConnRate:             5,
			ConnRateBurst:        20,
			Banner:               true,
		},
		Audit: newAuditSink(),
	}
}

// New builds a Server, loading host keys and wiring certificate auth.
func New(opts Options) (*Server, error) {
	if opts.Principals == nil {
		return nil, errors.New("sshd: Principals callback is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// On first boot the CA file may not exist yet (the first certificate sync
	// writes it). Start with whatever is available. Reload picks up the CA
	// once it lands.
	trusted := opts.TrustedCAs
	if len(trusted) == 0 {
		var err error
		trusted, err = loadTrustedCAs(opts.Tunables.DropRetiredCA)
		if err != nil {
			logger.Debug("trusted CAs unavailable, waiting for sync", "error", err)
		}
	}

	nologinFile := opts.NologinFile
	if nologinFile == "" {
		nologinFile = sysutil.NologinFile
	}

	s := &Server{
		logger:      logger,
		principals:  opts.Principals,
		revoked:     opts.RevokedBefore,
		audit:       opts.Audit,
		nologinFile: nologinFile,
		trustedCAs:  caKeys(trusted),
		limiters:    newLimiters(),
	}
	s.defaults = opts.Tunables
	s.tun.Store(&opts.Tunables)

	hostKeys, hostClosers, err := loadHostKeys()
	if err != nil {
		return nil, err
	}
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers
	s.cfg = s.serverConfig(hostKeys)

	logger.Debug("server configured", "host_keys", len(hostKeys), "trusted_cas", len(trusted))
	return s, nil
}

// SetTunables applies the runtime-tunable policy live, without restarting.
func (s *Server) SetTunables(t Tunables) {
	s.tun.Store(&t)
}

// Reload refreshes the trusted CAs and host keys from disk while serving. New
// connections use the fresh identity. Established connections are unaffected.
func (s *Server) Reload() error {
	dropRetired := s.tun.Load().DropRetiredCA
	trusted, caErr := loadTrustedCAs(dropRetired)
	if caErr != nil {
		// Keep the last known good set: a transient read error or a stray
		// unparseable line must not lock out every login until the next sync.
		s.logger.Warn("reload trusted CAs failed, keeping previous set", "error", caErr)
	}

	hostKeys, hostClosers, err := loadHostKeys()
	if err != nil {
		return err
	}

	s.certsMu.Lock()
	oldClosers := s.hostKeyClosers
	if caErr == nil {
		s.trustedCAs = caKeys(trusted)
	}
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers
	s.cfg = s.serverConfig(hostKeys)
	s.certsMu.Unlock()

	// Release the swapped-out identity's resources (TPM handles) now that no
	// handshake can pick them up anymore.
	for _, c := range oldClosers {
		if closeErr := c.Close(); closeErr != nil {
			s.logger.Debug("close replaced host key", "error", closeErr)
		}
	}

	s.logger.Debug(
		"reloaded identity",
		"host_keys",
		len(hostKeys),
		"trusted_cas",
		len(trusted),
	)
	return nil
}

// Serve accepts connections on l until l is closed.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.listener == nil {
		s.listener = l
	}
	s.mu.Unlock()

	var delay time.Duration
	for {
		nc, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			delay = min(2*delay+acceptBackoff, time.Second)
			s.logger.Error("accept failed", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if !s.acquireConn() {
			s.logger.Warn("dropping connection, at capacity", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		s.connsWg.Go(func() {
			defer s.releaseConn()
			s.HandleConn(nc)
		})
	}
}

// acquireConn reserves a slot for a new connection when a cap is configured.
// activeConns tracks the lifecycle regardless of the cap, keeping it live-adjustable.
func (s *Server) acquireConn() bool {
	limit := s.tun.Load().MaxConnections
	if limit > 0 {
		for {
			cur := s.activeConns.Load()
			if cur >= int64(limit) {
				return false
			}
			if s.activeConns.CompareAndSwap(cur, cur+1) {
				return true
			}
		}
	}
	s.activeConns.Add(1)
	return true
}

func (s *Server) releaseConn() {
	s.activeConns.Add(-1)
}

// acquireUnauthenticated reserves a slot for a connection still in the pre-auth
// handshake, so a brute force cannot exhaust the daemon ahead of authentication.
func (s *Server) acquireUnauthenticated() bool {
	limit := s.tun.Load().MaxStartups
	if limit <= 0 {
		return true
	}
	for {
		cur := s.unauthenticated.Load()
		if cur >= int64(limit) {
			return false
		}
		if s.unauthenticated.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (s *Server) releaseUnauthenticated() {
	s.unauthenticated.Add(-1)
}

// acquirePrincipalSession reserves a session slot for a principal, capping
// concurrent sessions per user across all connections. limit <= 0 disables it.
func (s *Server) acquirePrincipalSession(principal string, limit int) bool {
	if limit <= 0 {
		return true
	}
	s.principalMu.Lock()
	defer s.principalMu.Unlock()
	if s.principalSessions == nil {
		s.principalSessions = make(map[string]int)
	}
	if s.principalSessions[principal] >= limit {
		return false
	}
	s.principalSessions[principal]++
	return true
}

func (s *Server) releasePrincipalSession(principal string) {
	s.principalMu.Lock()
	defer s.principalMu.Unlock()
	if n := s.principalSessions[principal]; n <= 1 {
		delete(s.principalSessions, principal)
	} else {
		s.principalSessions[principal] = n - 1
	}
}

// Shutdown closes the listener, waits up to shutdownGrace for active connections
// to drain, then closes server resources. Safe to call more than once.
func (s *Server) Shutdown() error {
	s.mu.Lock()
	l := s.listener
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}

	done := make(chan struct{})
	go func() {
		s.connsWg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(shutdownGrace):
	}

	return s.Close()
}

// Close stops the listener and closes the audit sink and host keys, without
// killing active sessions. Safe to call more than once and concurrently with serving.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		l := s.listener
		s.mu.Unlock()
		if l != nil {
			_ = l.Close()
		}
		if s.audit != nil {
			if c, ok := s.audit.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
		s.certsMu.RLock()
		closers := append([]io.Closer(nil), s.hostKeyClosers...)
		s.certsMu.RUnlock()
		for _, c := range closers {
			if err := c.Close(); err != nil {
				s.logger.Debug("close host key", "error", err)
			}
		}
	})
	return nil
}

// ListenAndServe binds addr and serves on it, returning the bound address. It
// does not own shutdown: the caller calls Shutdown, and Serve errors are logged.
func (s *Server) ListenAndServe(ctx context.Context, addr string) (net.Addr, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	go func() {
		if serr := s.Serve(l); serr != nil {
			s.logger.Error("serve failed", "error", serr)
		}
	}()

	s.logger.Info("server listening", "addr", l.Addr().String())
	return l.Addr(), nil
}

func (s *Server) serverConfig(hostKeys []ssh.Signer) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		BannerCallback: func(ssh.ConnMetadata) string {
			return s.banner()
		},
		ServerVersion: "SSH-2.0-nokkud",
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	return cfg
}

// currentConfig returns the current server config under the certs lock so a
// concurrent Reload cannot race a handshake.
func (s *Server) currentConfig() *ssh.ServerConfig {
	s.certsMu.RLock()
	defer s.certsMu.RUnlock()
	return s.cfg
}

// HandleConn handles a single SSH connection on its own goroutine. A panic here
// must not take the daemon down, so the entry point recovers and logs it.
func (s *Server) HandleConn(nc net.Conn) {
	defer s.recoverAndLog("connection", func() { _ = nc.Close() })
	s.handleConn(nc)
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()

	// Cap the connection rate per source IP first, so a slow-drip brute force
	// never reaches the concurrency caps.
	if !s.allowConn(remoteIP(nc.RemoteAddr())) {
		s.logger.Warn(
			"dropping connection, rate limit exceeded",
			"remote",
			nc.RemoteAddr(),
		)
		return
	}

	// Cap concurrent pre-auth connections (MaxStartups).
	if !s.acquireUnauthenticated() {
		s.logger.Warn(
			"dropping connection, unauthenticated limit reached",
			"remote",
			nc.RemoteAddr(),
		)
		return
	}

	// Wrap the conn so inbound traffic refreshes a read deadline. The probing
	// goroutine disconnects a client that never responds.
	interval := s.tun.Load().ClientAliveInterval
	var alive *aliveConn
	if interval > 0 {
		alive = &aliveConn{Conn: nc, timeout: 3 * interval}
		nc = alive
	}

	conn, chans, reqs, err := s.handshake(nc)
	if err != nil {
		s.logger.Debug("handshake failed",
			"remote", nc.RemoteAddr(), "error", err)
		return
	}
	if err = nc.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}
	var aliveDone chan struct{}
	if alive != nil {
		alive.activate()
		aliveDone = make(chan struct{})
		go s.clientAlive(conn, interval, aliveDone)
	}

	s.logger.Info(
		"connection established",
		"user", conn.User(),
		"remote", conn.RemoteAddr(),
		"client", string(conn.ClientVersion()),
	)

	// Global requests: remote forwarding (tcpip-forward) and keepalives.
	st := newConnState(conn)
	go func() {
		defer s.recoverAndLog("global requests", nil)
		s.handleGlobalRequests(conn, st, reqs)
	}()

	var wg sync.WaitGroup
	defer func() {
		if aliveDone != nil {
			close(aliveDone)
		}
		st.close()
		wg.Wait()
		_ = conn.Close()
	}()

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			// Cap the channels one connection holds open, across types.
			if !st.acquireChannel(s.tun.Load().MaxChannels) {
				_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
				continue
			}
			wg.Go(func() {
				defer st.releaseChannel()
				_ = serveSessionChannel(s, conn, st, newCh)
			})
		case "direct-tcpip":
			// The handler owns the channel slot, since it must hold it for
			// the whole relay and not just the open request.
			wg.Go(func() { _ = serveDirectChannel(s, conn, st, newCh) })
		default:
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// handshake completes the SSH handshake while holding a MaxStartups slot for
// its duration only, and bounds a peer that never completes it with a deadline.
func (s *Server) handshake(nc net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	defer s.releaseUnauthenticated()
	if err := nc.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, nil, nil, err
	}
	return ssh.NewServerConn(nc, s.currentConfig())
}

// serveDirectChannel runs the direct-tcpip handler with the same panic
// containment as a session channel.
func serveDirectChannel(
	s *Server,
	conn *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
) (ch ssh.Channel) {
	defer s.recoverAndLog("channel direct-tcpip", func() {
		if ch != nil {
			_ = ch.Close()
			return
		}
		_ = newCh.Reject(ssh.ConnectionFailed, "channel handler failed")
	})
	return serveDirectTCPIP(s, conn, st, newCh)
}

// recoverAndLog contains a panic on the current goroutine, logs it with a stack
// trace, and runs cleanup. Every server goroutine defers it.
func (s *Server) recoverAndLog(where string, cleanup func()) {
	r := recover()
	if r == nil {
		return
	}
	s.logger.Error(
		"recovered panic",
		"where", where,
		"panic", r,
		"stack", string(debug.Stack()),
	)
	if cleanup != nil {
		func() {
			defer func() { _ = recover() }()
			cleanup()
		}()
	}
}
