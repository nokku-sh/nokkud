// Package sshd implements the embedded SSH server that replaces sshd on the
// host. It authenticates users by SSH certificate against the cached CA
// public key and principal map, runs sessions with the target user's
// privileges, and records and audits them inline.
package sshd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/state"
)

// PrincipalsFunc reports the subject UUIDs allowed to log in as username.
// The boolean reports whether access rules exist for the user at all.
type PrincipalsFunc func(username string) ([]string, bool)

// AuthorizeFunc runs after CA + principal checks and can deny the login
// (device trust, MFA, ...).
type AuthorizeFunc func(conn ssh.ConnMetadata, cert *ssh.Certificate, principal string) error

// Audit is the event sink for security events (auth, session, command,
// forwarding). Implementations must be safe for concurrent use.
type Audit interface {
	Emit(event audit.Event)
}

// SubsystemHandler serves a named SSH subsystem (e.g. "sftp") for a session.
// It runs with the session channel as its I/O and returns the exit status.
type SubsystemHandler func(sess *session) uint32

// Server is an SSH server. Construct with New and serve with Serve.
type Server struct {
	logger          *slog.Logger
	cfg             *ssh.ServerConfig
	paths           paths.Paths
	principals      PrincipalsFunc
	authorize       AuthorizeFunc
	audit           Audit
	record          atomic.Bool
	forwarding      atomic.Bool
	agentForwarding atomic.Bool
	gatewayPorts    atomic.Bool
	maxSessions     atomic.Int32

	// certsMu guards trustedCAs and hostKeys so a reload can swap them out
	// without tearing down established connections.
	certsMu    sync.RWMutex
	trustedCAs []ssh.PublicKey
	hostKeys   []ssh.Signer
	// hostKeyProvider rebuilds the host identity on Reload; hostKeyClosers
	// release the swapped-out identity's resources (e.g. TPM handles).
	hostKeyProvider func() ([]ssh.Signer, error)
	hostKeyClosers  []io.Closer

	// connection limits
	maxConns      int
	connSlots     chan struct{}
	aliveInterval time.Duration

	closeOnce sync.Once

	// mu guards the listener installed by ListenAndServe so Close can stop it.
	mu       sync.Mutex
	listener net.Listener

	// subsystemHandlers dispatches SSH subsystems ("sftp", ...) to handlers.
	subsystemHandlers map[string]SubsystemHandler
}

// Options configures a Server.
type Options struct {
	Logger *slog.Logger
	Paths  paths.Paths
	// Principals is required: it decides which cert principals may log in as
	// which local user.
	Principals PrincipalsFunc
	// Authorize is an optional post-auth policy hook: it runs after the
	// certificate passed the CA + principal checks and can deny the login
	// or enforce extensions / device trust / MFA.
	Authorize AuthorizeFunc
	// Audit is an optional sink for security events. When nil, no audit
	// events are emitted.
	Audit Audit
	// TrustedCAs lists the CA public keys that may sign user certificates.
	// When empty, the CAs are loaded from Paths.UserCAFile().
	TrustedCAs []ssh.PublicKey
	// HostKeys optionally supplies the server's host key signers; it is
	// called at startup and on every Reload. When nil, the default loader
	// is used: a TPM-resident host key when a TPM 2.0 is present,
	// otherwise the on-disk software key.
	HostKeys func() ([]ssh.Signer, error)
	// Record enables session recording via the recorder package.
	Record bool
	// AllowForwarding enables port forwarding (-L/-D via direct-tcpip channels,
	// -R via tcpip-forward). Disabled by default.
	AllowForwarding bool
	// AllowAgentForwarding enables auth-agent-req@openssh.com forwarding: the
	// client's ssh-agent is exposed to sessions via SSH_AUTH_SOCK. Disabled by
	// default.
	AllowAgentForwarding bool
	// GatewayPorts allows remote (-R) forwards to bind addresses other than
	// loopback. Like OpenSSH's GatewayPorts=no, the default forces every
	// remote forward onto 127.0.0.1, so an authorized user cannot expose a
	// service on the server's external interfaces.
	GatewayPorts bool
	// MaxSessions caps the number of session channels a single connection may
	// open (OpenSSH's MaxSessions). Zero means no per-connection cap.
	MaxSessions int
	// MaxConnections caps concurrent SSH connections (OpenSSH's MaxStartups).
	// Zero means no cap. Over-cap connections are dropped immediately.
	MaxConnections int
	// ClientAliveInterval is how often the server sends keepalive requests to
	// an idle client; a client that fails to respond for 3 intervals is
	// disconnected (OpenSSH's ClientAliveInterval). Zero disables probing.
	ClientAliveInterval time.Duration
}

// OptionsFrom returns the daemon's standard SSH server policy: the principal
// map from the shared cache, forwarding and agent forwarding on, a session
// cap, and the local audit sink. record enables session recording.
func OptionsFrom(p paths.Paths, cache *state.Cache, record bool) Options {
	return Options{
		Paths: p,
		Principals: func(username string) ([]string, bool) {
			return cache.GetUUIDs(username), true
		},
		Record:               record,
		AllowForwarding:      true,
		AllowAgentForwarding: true,
		MaxSessions:          10,
		MaxConnections:       100,
		ClientAliveInterval:  60 * time.Second,
		Audit:                newAuditSink(p),
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

	// On first boot the CA file may not exist yet (it is written by the first
	// certificate sync). Start with whatever is available; Reload picks up the
	// CA once it lands.
	trusted := opts.TrustedCAs
	if len(trusted) == 0 {
		var err error
		trusted, err = loadTrustedCAs(opts.Paths)
		if err != nil {
			logger.Debug("sshd: trusted CAs unavailable, waiting for sync", "error", err)
		}
	}

	s := &Server{
		logger:          logger,
		paths:           opts.Paths,
		principals:      opts.Principals,
		authorize:       opts.Authorize,
		audit:           opts.Audit,
		trustedCAs:      trusted,
		hostKeyProvider: opts.HostKeys,
		maxConns:        opts.MaxConnections,
		aliveInterval:   opts.ClientAliveInterval,
		subsystemHandlers: map[string]SubsystemHandler{
			sftpSubsystem: func(sess *session) uint32 { return sess.runSFTP() },
		},
	}
	s.record.Store(opts.Record)
	s.forwarding.Store(opts.AllowForwarding)
	s.agentForwarding.Store(opts.AllowAgentForwarding)
	s.gatewayPorts.Store(opts.GatewayPorts)
	s.maxSessions.Store(sessionCapToInt32(opts.MaxSessions))
	if opts.MaxConnections > 0 {
		s.connSlots = make(chan struct{}, opts.MaxConnections)
	}

	hostKeys, hostClosers, err := s.loadHostIdentity()
	if err != nil {
		return nil, err
	}
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		ServerVersion:     "SSH-2.0-nokkud",
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	s.cfg = cfg

	logger.Debug("sshd: server configured", "host_keys", len(hostKeys), "trusted_cas", len(trusted))
	return s, nil
}

// loadHostIdentity resolves the server's host key signers, preferring the
// configured provider and falling back to the default disk/TPM loader.
func (s *Server) loadHostIdentity() ([]ssh.Signer, []io.Closer, error) {
	if s.hostKeyProvider != nil {
		keys, err := s.hostKeyProvider()
		return keys, nil, err
	}
	return loadHostKeys(s.paths)
}

// Reload refreshes the trusted CAs and host keys from disk while serving:
// new connections use the fresh identity, established ones are unaffected.
// Called after a certificate sync so a renewed host cert or rotated CA
// applies without a restart.
func (s *Server) Reload() error {
	trusted, err := loadTrustedCAs(s.paths)
	if err != nil {
		// Fail closed: a CA that can no longer be read must not keep
		// granting logins from a stale in-memory list.
		s.logger.Warn("sshd: reload trusted CAs", "error", err)
	}

	hostKeys, hostClosers, err := s.loadHostIdentity()
	if err != nil {
		return err
	}

	s.certsMu.Lock()
	oldClosers := s.hostKeyClosers
	s.trustedCAs = trusted
	s.hostKeys = hostKeys
	s.hostKeyClosers = hostClosers
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		ServerVersion:     "SSH-2.0-nokkud",
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	s.cfg = cfg
	s.certsMu.Unlock()

	// Release the swapped-out identity's resources (TPM handles) now that
	// no handshake can pick them up anymore.
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

// Serve accepts connections on l until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		nc, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Error("sshd: accept", "error", err)
			continue
		}
		if !s.acquireConn() {
			s.logger.Warn("sshd: dropping connection, at capacity", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}
		go func() {
			defer s.releaseConn()
			s.HandleConn(nc)
		}()
	}
}

// acquireConn reserves a slot for a new connection when a cap is configured.
func (s *Server) acquireConn() bool {
	if s.connSlots == nil {
		return true
	}
	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConn() {
	if s.connSlots != nil {
		<-s.connSlots
	}
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

// sessionCapToInt32 bounds a configured session cap to a positive int32.
func sessionCapToInt32(n int) int32 {
	if n <= 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

// SetOptions applies runtime-tunable options (record, forwarding, session
// cap) live, without restarting. It replaces every tunable, so pass the full
// set: an unspecified field disables that feature.
func (s *Server) SetOptions(opts Options) {
	s.record.Store(opts.Record)
	s.forwarding.Store(opts.AllowForwarding)
	s.agentForwarding.Store(opts.AllowAgentForwarding)
	s.gatewayPorts.Store(opts.GatewayPorts)
	s.maxSessions.Store(sessionCapToInt32(opts.MaxSessions))
}

// SetRecord toggles session recording live, without touching the other
// tunables. It is driven by the backend's daemon config after each sync.
func (s *Server) SetRecord(record bool) {
	s.record.Store(record)
}

// ListenAndServe binds addr, starts serving on it, and returns the bound
// address. The listener closes automatically when ctx is cancelled, so the
// daemon's lifecycle is driven by a single context. Serve errors are logged
// rather than returned; use Serve directly when the caller needs them.
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
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	s.logger.Info("sshd: server listening", "addr", l.Addr().String())
	return l.Addr(), nil
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

	// Client-alive probing: wrap the conn so inbound traffic refreshes a
	// read deadline; the probing goroutine disconnects a client that never
	// responds.
	var alive *aliveConn
	if s.aliveInterval > 0 {
		alive = &aliveConn{Conn: nc, timeout: 3 * s.aliveInterval}
		nc = alive
	}

	// Bound the handshake: a peer that never completes it must not hold a
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
		go s.clientAlive(conn, s.aliveInterval, aliveDone)
	}

	s.logger.Info(
		"sshd: connection established",
		"user", conn.User(),
		"remote", conn.RemoteAddr(),
		"client", string(conn.ClientVersion()),
	)

	// Global requests: remote forwarding (tcpip-forward) and keepalives.
	st := newConnState(conn)
	go s.handleGlobalRequests(conn, st, reqs)

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
			// A handler may reject the channel without accepting it, so
			// there may be no channel to close on panic; a late Reject
			// is a no-op and closes the pending channel.
			var ch ssh.Channel
			defer s.recoverAndLog("channel "+newCh.ChannelType(), func() {
				if ch != nil {
					_ = ch.Close()
					return
				}
				_ = newCh.Reject(ssh.ConnectionFailed, "channel handler failed")
			})
			handler(s, conn, st, newCh, &ch)
		})
	}
}

// channelHandler serves one accepted SSH channel type.
type channelHandler func(*Server, *ssh.ServerConn, *connState, ssh.NewChannel, *ssh.Channel)

// channelHandlers maps SSH channel types to handlers ("session",
// "direct-tcpip") so new types slot in without touching the accept loop.
var channelHandlers = map[string]channelHandler{
	"session":      (*Server).handleSession,
	"direct-tcpip": (*Server).serveDirectTCPIP,
}

// handleSession accepts a "session" channel and serves its request stream,
// enforcing the per-connection session cap.
func (s *Server) handleSession(
	conn *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
	ch *ssh.Channel,
) {
	if !st.acquireSession(int(s.maxSessions.Load())) {
		_ = newCh.Reject(ssh.ResourceShortage, "too many sessions")
		return
	}
	defer st.releaseSession()
	c, reqs, err := newCh.Accept()
	if err != nil {
		s.logger.Debug("sshd: accept session channel", "error", err)
		return
	}
	*ch = c
	s.serveSession(conn, c, reqs)
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
