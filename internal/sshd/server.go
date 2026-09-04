// Package sshd implements the embedded SSH server. It authenticates users by
// certificate against the cached CA and principal map, then runs and records
// their sessions inline.
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
)

// PrincipalsFunc reports the subject UUIDs allowed to log in as username. An
// empty result denies access.
type PrincipalsFunc func(username string) []string

// AuthorizeFunc runs after CA and principal checks and can deny the login.
type AuthorizeFunc func(conn ssh.ConnMetadata, cert *ssh.Certificate, principal string) error

// Audit is the event sink for security events. Safe for concurrent use.
type Audit interface {
	Emit(event audit.Event)
}

// SubsystemHandler serves a named SSH subsystem (e.g. "sftp") for a session.
type SubsystemHandler func(sess *session) uint32

// shutdownGrace bounds how long Shutdown waits for active connections to
// drain before closing resources regardless. It is fixed rather than passed
// as a context so the daemon's lifecycle is driven by a single context that
// flows top-down; the server never manufactures its own shutdown context.
const shutdownGrace = 10 * time.Second

// Server is an SSH server. Construct with New and serve with Serve.
type Server struct {
	logger     *slog.Logger
	cfg        *ssh.ServerConfig
	principals PrincipalsFunc
	authorize  AuthorizeFunc
	audit      Audit

	// tun holds the live-adjustable options. It is swapped atomically so a
	// concurrent SetTunables never tears down established connections.
	tun atomic.Pointer[Tunables]
	// defaults are the tunables the server was constructed with.
	// DefaultTunables returns them so the client can overlay a synced
	// backend config on the compiled-in policy rather than the previous
	// live state. Never mutated after New.
	defaults Tunables

	// certsMu guards trustedCAs and hostKeys so a reload can swap them out
	// without tearing down established connections.
	certsMu    sync.RWMutex
	trustedCAs []ssh.PublicKey
	hostKeys   []ssh.Signer
	// hostKeyProvider rebuilds the host identity on Reload. hostKeyClosers
	// release the swapped-out identity's resources (e.g. TPM handles).
	hostKeyProvider func() ([]ssh.Signer, error)
	hostKeyClosers  []io.Closer

	// connection limits
	activeConns     atomic.Int64
	unauthenticated atomic.Int64
	closeOnce       sync.Once
	connsWg         sync.WaitGroup

	// principalSessions counts active sessions per principal (SSH username)
	// so one user cannot exhaust the daemon across many connections.
	principalMu       sync.Mutex
	principalSessions map[string]int

	// limiters is a bounded per-source-IP cache of connection rate limiters.
	// Rate and burst come from the live tunables so SetTunables applies
	// without rebuilding the cache.
	limiters *lru.Cache[string, *rate.Limiter]

	// mu guards the listener installed by ListenAndServe so Close can stop it.
	mu       sync.Mutex
	listener net.Listener

	// subsystemHandlers dispatches SSH subsystems ("sftp", ...) to handlers.
	subsystemHandlers map[string]SubsystemHandler

	// recordingSinkFactory builds the upload sink for a session's recorder.
	// The client wires it so the SSH server can stream recordings without
	// knowing the API client. Nil disables uploading (local recording only).
	// The ctx passed to the factory must not be canceled by the session
	// ending: uploads continue while the session tears down.
	recordingSinkFactory func(ctx context.Context, sessionID, username string) io.WriteCloser
}

// SetRecordingSinkFactory installs the factory used to create per-session
// recording upload sinks. Set once by the client at startup.
func (s *Server) SetRecordingSinkFactory(
	fn func(ctx context.Context, sessionID, username string) io.WriteCloser,
) {
	s.recordingSinkFactory = fn
}

// Tunables is the live-adjustable subset of the server policy. The backend
// can change any field at runtime through the synced daemon config; a
// concurrent SetTunables swaps them without touching established
// connections.
type Tunables struct {
	// Record enables session recording via the recorder package.
	Record bool
	// AllowForwarding enables port forwarding (-L/-D and -R). Disabled by
	// default.
	AllowForwarding bool
	// AllowAgentForwarding enables auth-agent-req@openssh.com forwarding. The
	// client's ssh-agent is exposed to sessions via SSH_AUTH_SOCK.
	AllowAgentForwarding bool
	// GatewayPorts allows remote (-R) forwards to bind addresses other than
	// loopback. Like OpenSSH's GatewayPorts=no, the default pins every remote
	// forward to 127.0.0.1 so a user cannot expose a service on the server's
	// external interfaces.
	GatewayPorts bool
	// MaxSessions caps session channels per connection (OpenSSH's MaxSessions).
	// Zero means no per-connection cap.
	MaxSessions int
	// MaxConnections caps concurrent SSH connections. Zero means no cap.
	// Over-cap connections are dropped immediately.
	MaxConnections int
	// MaxStartups caps concurrent connections still in the pre-auth handshake
	// (OpenSSH's MaxStartups). Zero means no cap. This bounds brute-force and
	// half-open floods without affecting authenticated users behind a NAT.
	MaxStartups int
	// MaxSessionsPerUser caps concurrent sessions per authenticated principal
	// (SSH username) across all connections, for fairness between users. Zero
	// means no per-user cap.
	MaxSessionsPerUser int
	// ClientAliveInterval is how often the server sends keepalive requests to
	// an idle client. A client that fails to respond for 3 intervals is
	// disconnected (OpenSSH's ClientAliveInterval). Zero disables probing.
	ClientAliveInterval time.Duration
	// ConnRate caps new connections per second per source IP, with
	// ConnRateBurst allowing short bursts above the steady rate. Together
	// they stop a slow-drip brute force that stays under MaxStartups. Zero
	// disables rate limiting.
	ConnRate int
	// ConnRateBurst allows short bursts above ConnRate.
	ConnRateBurst int
	// Banner enables the pre-auth banner describing session policy.
	Banner bool
}

// Options configures a Server.
type Options struct {
	Logger *slog.Logger
	// Principals decides which cert principals may log in as which user.
	Principals PrincipalsFunc
	// Authorize is an optional post-auth policy hook, e.g. device trust or MFA.
	Authorize AuthorizeFunc
	// Audit is an optional sink for security events.
	Audit Audit
	// TrustedCAs lists the CA public keys that may sign user certificates.
	// When empty, the CAs are loaded from Paths.UserCAFile().
	TrustedCAs []ssh.PublicKey
	// HostKeys optionally supplies the server's host key signers. Called at
	// startup and on every Reload. Defaults to a TPM-resident host key when a
	// TPM 2.0 is present, otherwise the on-disk software key.
	HostKeys func() ([]ssh.Signer, error)
	// Tunables is the compiled-in live-adjustable policy. The backend may
	// override any of it at runtime through the synced daemon config.
	Tunables Tunables
}

// DefaultTunables returns the compiled-in tunables the server was
// constructed with. The client overlays the backend's synced daemon config
// on top of these so an unset field falls back to the policy compiled into
// the daemon instead of silently disabling the feature or inheriting a
// previous backend value.
func (s *Server) DefaultTunables() Tunables {
	return s.defaults
}

// OptionsFrom returns the daemon's standard SSH server policy. It wires the
// shared cache, forwarding, a session cap, and the local audit sink. record
// enables session recording. These are the compiled-in defaults; the backend
// may override any of them live through the synced daemon config.
func OptionsFrom(cache *state.Cache, record bool) Options {
	return Options{
		Principals: func(username string) []string {
			return cache.GetUUIDs(username)
		},
		Tunables: Tunables{
			Record:               record,
			AllowForwarding:      true,
			AllowAgentForwarding: true,
			MaxSessions:          10,
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
		trusted, err = loadTrustedCAs()
		if err != nil {
			logger.Debug("sshd: trusted CAs unavailable, waiting for sync", "error", err)
		}
	}

	s := &Server{
		logger:          logger,
		principals:      opts.Principals,
		authorize:       opts.Authorize,
		audit:           opts.Audit,
		trustedCAs:      trusted,
		hostKeyProvider: opts.HostKeys,
		limiters:        newLimiters(),
		subsystemHandlers: map[string]SubsystemHandler{
			sftpSubsystem: func(sess *session) uint32 { return sess.runSFTP() },
		},
	}
	s.defaults = opts.Tunables
	s.tun.Store(&opts.Tunables)

	hostKeys, hostClosers, err := s.loadHostIdentity()
	if err != nil {
		return nil, err
	}
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers
	s.cfg = s.serverConfig(hostKeys)

	logger.Debug("sshd: server configured", "host_keys", len(hostKeys), "trusted_cas", len(trusted))
	return s, nil
}

// SetTunables applies the runtime-tunable policy (record, forwarding,
// session and connection caps, client-alive interval) live, without
// restarting.
func (s *Server) SetTunables(t Tunables) {
	s.tun.Store(&t)
}

// loadHostIdentity resolves the server's host key signers, preferring the
// configured provider and falling back to the default disk/TPM loader.
func (s *Server) loadHostIdentity() ([]ssh.Signer, []io.Closer, error) {
	if s.hostKeyProvider != nil {
		keys, err := s.hostKeyProvider()
		return keys, nil, err
	}
	return loadHostKeys()
}

// Reload refreshes the trusted CAs and host keys from disk while serving.
// New connections use the fresh identity. Established ones are unaffected.
// Called after a certificate sync so a renewed host cert or rotated CA
// applies without a restart.
func (s *Server) Reload() error {
	trusted, caErr := loadTrustedCAs()
	if caErr != nil {
		// Keep the last known good set. A transient read error or a stray
		// unparseable line must not lock out every login until the next sync.
		// A genuinely rotated-out CA stops working because its certificates
		// expire, not because reload failed.
		s.logger.Warn("sshd: reload trusted CAs, keeping previous set", "error", caErr)
	}

	hostKeys, hostClosers, err := s.loadHostIdentity()
	if err != nil {
		return err
	}

	s.certsMu.Lock()
	oldClosers := s.hostKeyClosers
	if caErr == nil {
		s.trustedCAs = trusted
	}
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers
	s.cfg = s.serverConfig(hostKeys)
	s.certsMu.Unlock()

	// Release the swapped-out identity's resources (TPM handles) now that no
	// handshake can pick them up anymore.
	for _, c := range oldClosers {
		if closeErr := c.Close(); closeErr != nil {
			s.logger.Debug("sshd: close replaced host key", "error", closeErr)
		}
	}

	s.logger.Debug(
		"sshd: reloaded identity",
		"host_keys",
		len(hostKeys),
		"trusted_cas",
		len(trusted),
	)
	return nil
}

// acceptBackoff bounds the retry delay when Accept keeps failing on a live
// listener (EMFILE under fd exhaustion is the classic case). Without it the
// accept loop would spin a core and flood the log.
const acceptBackoff = 10 * time.Millisecond

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
			s.logger.Error("sshd: accept", "error", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if !s.acquireConn() {
			s.logger.Warn("sshd: dropping connection, at capacity", "remote", nc.RemoteAddr())
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
// activeConns is kept in lockstep with the connection lifecycle regardless of
// the cap, so re-enabling the cap later starts from an accurate count. The
// counter approach keeps the cap live-adjustable: a concurrent SetTunables
// swaps the cap without tearing down established connections.
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

// acquireUnauthenticated reserves a slot for a connection still in the
// pre-auth handshake. It caps concurrent half-open connections so a brute
// force or SYN flood cannot exhaust the daemon ahead of authentication.
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
// concurrent sessions per user across all connections. limit <= 0 disables
// the cap.
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

// Shutdown gracefully drains active connections. It closes the listener to
// stop accepting new connections and blocks until all active connections have
// completed, or until shutdownGrace elapses. It always closes the server
// resources (host keys, audit logs) before returning. Safe to call more than
// once and concurrently with serving.
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

// Close stops the listener (if ListenAndServe started one) and closes the
// audit sink. It does not forcibly kill active sessions. Safe to call more
// than once and concurrently with serving.
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
				s.logger.Debug("sshd: close host key", "error", err)
			}
		}
	})
	return nil
}

// ListenAndServe binds addr and starts serving on it, returning the bound
// address. It does not own the server's shutdown: the caller calls Shutdown
// (e.g. when its context is cancelled) to stop accepting and drain. Serve
// errors are logged rather than returned. Use Serve directly when the caller
// needs them.
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
			s.logger.Error("sshd: serve", "error", serr)
		}
	}()

	s.logger.Info("sshd: server listening", "addr", l.Addr().String())
	return l.Addr(), nil
}

// serverConfig builds the SSH server config for the given host keys.
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

// HandleConn handles a single SSH connection on its own goroutine. A panic
// anywhere on this goroutine must not take the daemon down, so the entry
// point recovers and logs it.
func (s *Server) HandleConn(nc net.Conn) {
	defer s.recoverAndLog("connection", func() { _ = nc.Close() })
	s.handleConn(nc)
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()

	// Cap the connection rate per source IP before anything else. A
	// slow-drip brute force never reaches the concurrency caps.
	if !s.allowConn(remoteIP(nc.RemoteAddr())) {
		s.logger.Warn(
			"sshd: dropping connection, rate limit exceeded",
			"remote",
			nc.RemoteAddr(),
		)
		return
	}

	// Cap concurrent pre-auth connections (MaxStartups). The slot is released
	// as soon as the handshake finishes, success or not.
	if !s.acquireUnauthenticated() {
		s.logger.Warn(
			"sshd: dropping connection, unauthenticated limit reached",
			"remote",
			nc.RemoteAddr(),
		)
		return
	}
	defer s.releaseUnauthenticated()

	// Client-alive probing. Wrap the conn so inbound traffic refreshes a
	// read deadline. The probing goroutine disconnects a client that never
	// responds.
	interval := s.tun.Load().ClientAliveInterval
	var alive *aliveConn
	if interval > 0 {
		alive = &aliveConn{Conn: nc, timeout: 3 * interval}
		nc = alive
	}

	// Bound the handshake. A peer that never completes it must not hold a
	// goroutine or connection open forever.
	if err := nc.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.currentConfig())
	if err != nil {
		s.logger.Debug("sshd: handshake failed",
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
		"sshd: connection established",
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
		handler, ok := channelHandlers[newCh.ChannelType()]
		if !ok {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		wg.Go(func() {
			_ = handler(s, conn, st, newCh)
		})
	}
}

// recoverAndLog contains a panic on the current goroutine, logs it with a
// stack trace, and runs cleanup. Every goroutine the server starts defers
// this so a single session or connection cannot take the daemon down.
func (s *Server) recoverAndLog(where string, cleanup func()) {
	r := recover()
	if r == nil {
		return
	}
	s.logger.Error(
		"sshd: recovered panic",
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
