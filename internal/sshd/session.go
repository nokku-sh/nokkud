package sshd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/ptysession"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// channelHandler serves one accepted SSH channel type.
type channelHandler func(*Server, *ssh.ServerConn, *connState, ssh.NewChannel, *ssh.Channel)

// channelHandlers maps SSH channel types to handlers so new types slot in
// without touching the accept loop.
var channelHandlers = map[string]channelHandler{
	"session":      (*Server).handleSession,
	"direct-tcpip": (*Server).serveDirectTCPIP,
}

// handleSession accepts a "session" channel and serves its request stream,
// enforcing the per-connection session cap and the per-principal session cap.
func (s *Server) handleSession(
	conn *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
	ch *ssh.Channel,
) {
	if !st.acquireSession(s.tun.Load().MaxSessions) {
		_ = newCh.Reject(ssh.ResourceShortage, "too many sessions")
		return
	}
	defer st.releaseSession()

	if !s.acquirePrincipalSession(conn.User(), s.tun.Load().MaxSessionsPerUser) {
		_ = newCh.Reject(ssh.ResourceShortage, "too many sessions for user")
		return
	}
	defer s.releasePrincipalSession(conn.User())

	c, reqs, err := newCh.Accept()
	if err != nil {
		s.logger.Debug("sshd: accept session channel", "error", err)
		return
	}
	*ch = c
	s.serveSession(conn, c, reqs)
}

// session handles a single "session" channel. It embeds the SSH channel so
// handlers write to it directly, and exposes the request state (env,
// command, subsystem) plus a single teardown path via Exit.
type session struct {
	ssh.Channel

	server  *Server
	conn    *ssh.ServerConn
	reqs    <-chan *ssh.Request
	sysUser *user.User
	shell   string

	// ctx is canceled when the session ends. Exec'd commands use it so a
	// disconnect reaps them even if the request stream misbehaves.
	ctx    context.Context
	cancel context.CancelFunc

	env     []string
	rawCmd  string
	handled bool

	// sessionID correlates audit events for one session channel.
	sessionID string

	// agent forwarding: listener + socket path for SSH_AUTH_SOCK
	agentLn   net.Listener
	agentSock string

	ptmx pty.Pty
	rec  *recording.Recorder

	exitMu sync.Mutex
	exited bool

	procMu   sync.Mutex
	proc     *os.Process
	wantKill bool

	// pendingSignals buffers signals that arrived before the command started.
	// They are flushed to the process once it exists. Guarded by procMu.
	pendingSignals []os.Signal
}

// serveSession runs the request loop for a session channel.
func (s *Server) serveSession(conn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	sysUser, err := sysutil.LookupUser(conn.User())
	if err != nil {
		s.emit(
			eventWith(
				connEvent(conn),
				audit.EventAuthFailure,
				"",
				fmt.Sprintf("user %q not found", conn.User()),
			),
		)
		s.authFailure(conn, fmt.Errorf("user %q not found", conn.User()))
		_ = ch.Close()
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		s.logger.Debug("sshd: session id", "error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := &session{
		Channel:   ch,
		server:    s,
		conn:      conn,
		reqs:      reqs,
		sysUser:   sysUser,
		shell:     sysutil.UserShell(sysUser),
		ctx:       ctx,
		cancel:    cancel,
		sessionID: sessionID,
	}

	ev := eventWith(connEvent(conn), audit.EventSessionStart, "", "")
	ev.SessionID = sessionID
	ev.User = sysUser.Username
	s.emit(ev)

	defer cancel()
	sess.handleRequests()
}

// handleRequests processes the session request stream. shell/exec/subsystem
// start the work in a handler goroutine while this loop keeps servicing
// window-change and signal requests. When the stream ends (client
// disconnect) the running process is killed and the handler is joined.
func (sess *session) handleRequests() {
	handlerDone := make(chan struct{})
	var started bool
	var start sync.Once
	startHandler := func(fn func()) {
		start.Do(func() {
			started = true
			go func() {
				defer close(handlerDone)
				defer sess.server.recoverAndLog("session handler", nil)
				fn()
			}()
		})
	}

	for req := range sess.reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handleCommand(req) {
				startHandler(func() { sess.run() })
			}
		case "subsystem":
			if name, ok := sess.acceptSubsystem(req); ok {
				startHandler(func() { sess.Exit(int(sess.runSubsystem(name))) })
			}
		case "env":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}
			var e struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &e) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			if !sess.acceptEnv(e.Name) {
				_ = req.Reply(false, nil)
				continue
			}
			sess.env = append(sess.env, e.Name+"="+e.Value)
			_ = req.Reply(true, nil)
		case "pty-req":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}
			sess.ptyReq(req)
		case agentRequestType:
			if sess.agentRequest(req) {
				go func() {
					defer sess.server.recoverAndLog("agent forwarding", nil)
					sess.serveAgent()
				}()
			}
		case "window-change":
			sess.windowChange(req)
		case "signal":
			sess.signal(req)
		default:
			_ = req.Reply(false, nil)
		}
	}

	// Client disconnected (or the session channel closed): reap any
	// running process, then wait for the handler to wind down. If no
	// handler ever started there is nothing to join.
	sess.killProc()
	if started {
		<-handlerDone
	}
}

// handleCommand handles a shell/exec request. It replies and returns true
// when the session should start running the command.
func (sess *session) handleCommand(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}

	// A certificate force-command critical option replaces whatever the
	// client asked for (matching sshd). The requested command is ignored.
	if fc := sess.forceCommand(); fc != "" {
		sess.rawCmd = fc
	} else if req.Type == "exec" {
		var e struct{ Command string }
		if ssh.Unmarshal(req.Payload, &e) != nil {
			_ = req.Reply(false, nil)
			return false
		}
		sess.rawCmd = e.Command
	}
	sess.handled = true
	_ = req.Reply(true, nil)

	ev := eventWith(connEvent(sess.conn), audit.EventCommand, "", "")
	ev.SessionID = sess.sessionID
	ev.User = sess.sysUser.Username
	ev.Command = sess.rawCmd
	sess.server.emit(ev)
	return true
}

// forceCommand returns the certificate's force-command critical option, or ""
// when none is set.
func (sess *session) forceCommand() string {
	if sess.conn == nil || sess.conn.Permissions == nil {
		return ""
	}
	return sess.conn.Permissions.Extensions["force-command"]
}

// acceptEnv applies the client environment whitelist (the SSH equivalent
// of OpenSSH's AcceptEnv). A certificate force-command refuses client-
// supplied environment entirely, so an injected BASH_ENV or LD_PRELOAD
// cannot override a restricted command.
func (sess *session) acceptEnv(name string) bool {
	if sess.forceCommand() != "" {
		return false
	}
	return allowedEnv(name)
}

// allowedEnv reports whether a client env request variable may reach the
// session. Only locale/terminal hints are trusted. Anything that could
// influence program loading or the shell (PATH, LD_*, BASH_ENV, ENV) or
// override daemon-set session metadata (SSH_*) is refused.
func allowedEnv(name string) bool {
	switch name {
	case "TERM", "LANG", "TZ", "TERM_PROGRAM", "COLORTERM":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

// setEnv sets a session environment variable, replacing any existing entry so
// the last-set value wins regardless of request order.
func (sess *session) setEnv(key, value string) {
	kv := key + "="
	for i, e := range sess.env {
		if strings.HasPrefix(e, kv) {
			sess.env[i] = kv + value
			return
		}
	}
	sess.env = append(sess.env, kv+value)
}

// acceptSubsystem handles a subsystem request. It replies and returns the
// subsystem name when a handler is registered for it.
func (sess *session) acceptSubsystem(req *ssh.Request) (string, bool) {
	if sess.handled {
		_ = req.Reply(false, nil)
		return "", false
	}
	if sess.forceCommand() != "" {
		// A force-command takes precedence over subsystems, matching sshd.
		_ = req.Reply(false, nil)
		return "", false
	}
	var r struct{ Name string }
	if ssh.Unmarshal(req.Payload, &r) != nil {
		_ = req.Reply(false, nil)
		return "", false
	}
	if _, ok := sess.server.subsystemHandlers[r.Name]; !ok {
		_ = req.Reply(false, nil)
		return "", false
	}
	sess.handled = true
	_ = req.Reply(true, nil)
	return r.Name, true
}

// runSubsystem serves the requested subsystem and returns its exit status.
func (sess *session) runSubsystem(name string) uint32 {
	if handler, ok := sess.server.subsystemHandlers[name]; ok {
		return handler(sess)
	}
	return 1
}

// User returns the username the client authenticated as.
func (sess *session) User() string {
	return sess.conn.User()
}

// RemoteAddr returns the client's address.
func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

// Environ returns a copy of the environment set by the client.
func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

// RawCommand returns the exact command the client requested.
func (sess *session) RawCommand() string {
	return sess.rawCmd
}

// pty-req: string TERM, uint32 width, uint32 height, uint32 width_px,
// uint32 height_px, string modes.
func (sess *session) ptyReq(req *ssh.Request) {
	var r struct {
		Term     string
		Width    uint32
		Height   uint32
		WidthPx  uint32
		HeightPx uint32
		Modes    []byte
	}
	if ssh.Unmarshal(req.Payload, &r) != nil {
		_ = req.Reply(false, nil)
		return
	}

	ptmx, err := pty.New()
	if err != nil {
		sess.server.logger.Debug("sshd: open pty", "error", err)
		_ = req.Reply(false, nil)
		return
	}
	if err = ptmx.Resize(int(r.Width), int(r.Height)); err != nil {
		_ = ptmx.Close()
		_ = req.Reply(false, nil)
		return
	}
	sess.ptmx = ptmx
	sess.setEnv("TERM", r.Term)

	if sess.server.tun.Load().Record && sess.server.paths.RecordsDir != "" {
		var sink io.WriteCloser
		if sess.server.recordingSinkFactory != nil {
			sink = sess.server.recordingSinkFactory(sess.sessionID, sess.sysUser.Username)
		}
		var rec *recording.Recorder
		rec, err = recording.New(sess.server.paths, recording.Options{
			Width:         int(r.Width),
			Height:        int(r.Height),
			Title:         fmt.Sprintf("ssh-%s", sess.sysUser.Username),
			Label:         sess.sysUser.Username,
			SessionID:     sess.sessionID,
			RedactSecrets: true,
			Sink:          sink,
		})
		if err == nil && rec != nil {
			sess.rec = rec
		}
	}
	_ = req.Reply(true, nil)
}

// window-change: uint32 cols, uint32 rows, uint32 width_px, uint32 height_px.
func (sess *session) windowChange(req *ssh.Request) {
	var w struct{ Cols, Rows, W, H uint32 }
	if ssh.Unmarshal(req.Payload, &w) == nil && sess.ptmx != nil {
		if err := sess.ptmx.Resize(int(w.Cols), int(w.Rows)); err != nil {
			sess.server.logger.Debug("sshd: resize pty", "error", err)
		}
	}
	_ = req.Reply(true, nil)
}

// signal forwards a channel signal to the running process. Signals that
// arrive before the command starts are buffered and delivered on start.
func (sess *session) signal(req *ssh.Request) {
	var sg struct{ Signal string }
	if ssh.Unmarshal(req.Payload, &sg) != nil {
		_ = req.Reply(false, nil)
		return
	}
	sig, ok := signalByName(sg.Signal)
	if !ok {
		_ = req.Reply(false, nil)
		return
	}
	sess.procMu.Lock()
	defer sess.procMu.Unlock()
	if p := sess.proc; p != nil {
		_ = p.Signal(sig)
	} else {
		sess.pendingSignals = append(sess.pendingSignals, sig)
	}
	_ = req.Reply(true, nil)
}

func (sess *session) setProc(p *os.Process) {
	sess.procMu.Lock()
	defer sess.procMu.Unlock()
	if sess.wantKill {
		_ = p.Kill()
		return
	}
	sess.proc = p
	for _, sig := range sess.pendingSignals {
		_ = p.Signal(sig)
	}
	sess.pendingSignals = nil
}

func (sess *session) killProc() {
	sess.procMu.Lock()
	defer sess.procMu.Unlock()
	sess.wantKill = true
	if sess.proc != nil {
		_ = sess.proc.Kill()
	}
}

// Exit reports the exit status and closes the session channel. Safe to call
// multiple times. Only the first call has an effect.
func (sess *session) Exit(code int) {
	sess.finish(code, func() {
		status := struct{ Status uint32 }{exitCodeToU32(code)}
		_, _ = sess.SendRequest("exit-status", false, ssh.Marshal(status))
	})
}

// ExitProcess reports a finished process the way OpenSSH does. exit-status
// for a normal exit, exit-signal when the command died by signal, so clients
// surface 128+signal (137 for SIGKILL, 143 for SIGTERM).
func (sess *session) ExitProcess(st *os.ProcessState) {
	name, code, signaled := processSignal(st)
	if !signaled {
		sess.Exit(int(exitCodeOf(st)))
		return
	}
	if name == "" {
		// Signal outside the RFC 4254 name table: still surface 128+n.
		sess.Exit(code)
		return
	}
	sess.exitSignal(name, code)
}

// exitSignal reports that the command was killed by a signal. It sends an
// exit-signal channel request (RFC 4254 section 6.10) instead of exit-status.
func (sess *session) exitSignal(name string, code int) {
	sess.finish(code, func() {
		sig := struct {
			Signal     string
			CoreDumped bool
			Message    string
			Language   string
		}{Signal: name}
		_, _ = sess.SendRequest("exit-signal", false, ssh.Marshal(sig))
	})
}

// finish is the single teardown path for a session. It emits the session_end
// audit event, delivers the terminal channel request via send, and closes the
// channel.
func (sess *session) finish(code int, send func()) {
	sess.exitMu.Lock()
	defer sess.exitMu.Unlock()
	if sess.exited {
		return
	}
	sess.exited = true
	sess.cancel()

	if sess.rec != nil {
		sess.rec.RecordExit(code)
		sess.rec.Close()
	}

	ev := eventWith(connEvent(sess.conn), audit.EventSessionEnd, "", "")
	ev.SessionID = sess.sessionID
	ev.User = sess.sysUser.Username
	ev.ExitCode = code
	sess.server.emit(ev)

	send()
	_ = sess.Close()
}

// run dispatches to the pty or plain execution path.
func (sess *session) run() {
	if sess.ptmx != nil {
		sess.runPTY()
		return
	}
	sess.runPlain()
}

// runPTY runs the command attached to the pty, relaying stdin/stdout and
// recording when enabled.
func (sess *session) runPTY() {
	cmd := sess.ptmx.Command(sess.shell)
	if err := ptysession.Configure(
		cmd,
		sess.sysUser,
		sess.shell,
		sess.rawCmd,
		sess.buildEnv(),
	); err != nil {
		sess.Exit(1)
		return
	}

	ps, waitInput := ptysession.Run(ptysession.RunOptions{
		Pty:     sess.ptmx,
		Cmd:     cmd,
		In:      sess,
		Out:     sess,
		Rec:     sess.rec,
		OnStart: sess.setProc,
	})

	// ExitProcess closes the session channel, which unblocks the input relay
	// Run spawned; join it afterwards.
	sess.ExitProcess(ps)
	waitInput()
}

// runPlain runs the command without a pty, wiring the channel straight to
// the process (the non-interactive `ssh host command` path).
func (sess *session) runPlain() {
	var cmd *exec.Cmd
	// #nosec G204 - running the authenticated user's command is the SSH
	// server's purpose. The process is spawned with that user's privileges.
	if sess.rawCmd == "" {
		cmd = exec.CommandContext(sess.ctx, sess.shell)
	} else {
		cmd = exec.CommandContext(sess.ctx, sess.shell, "-c", sess.rawCmd)
	}
	cmd.Dir = sess.sysUser.HomeDir
	cmd.Env = sess.buildEnv()
	attr, err := sysutil.SysProcAttr(sess.sysUser)
	if err != nil {
		sess.Exit(1)
		return
	}
	cmd.SysProcAttr = attr

	// Stderr goes to the channel's extended data stream (like sshd), not
	// the regular data stream. Binary protocols (rsync, git, scp -s) are
	// length-prefixed and break if stderr bytes are interleaved.
	sess.runProcess(cmd, sess.Stderr())
}

// runProcess starts cmd and relays the session channel to its stdin/stdout
// until the process exits, then reports the exit via ExitProcess and rejoins
// the relay goroutines. errW, when non-nil, is wired to the process stderr.
// The caller must configure the command beforehand (args, env, dir,
// privileges). It returns the process state so a caller can derive a code.
func (sess *session) runProcess(cmd *exec.Cmd, errW io.Writer) *os.ProcessState {
	if errW != nil {
		cmd.Stderr = errW
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		sess.server.logger.Debug("sshd: process stdin pipe", "error", err)
		sess.Exit(1)
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		sess.server.logger.Debug("sshd: process stdout pipe", "error", err)
		sess.Exit(1)
		return nil
	}

	if err = cmd.Start(); err != nil {
		sess.server.logger.Debug("sshd: start command", "error", err)
		_ = stdin.Close()
		_ = stdout.Close()
		sess.Exit(1)
		return nil
	}
	sess.setProc(cmd.Process)

	var relay sync.WaitGroup

	// client -> process
	relay.Go(func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	})

	// process -> client. A length-prefixed protocol (rsync) reads stderr
	// as extended data, so stdout is the only thing on the data stream.
	stdoutDone := make(chan struct{})
	relay.Go(func() {
		defer close(stdoutDone)
		_, _ = io.Copy(sess, stdout)
	})

	// Drain stdout before reaping. cmd.Wait() closes the stdout pipe,
	// which would truncate output the relay has not yet copied.
	<-stdoutDone
	if waitErr := cmd.Wait(); waitErr != nil {
		sess.server.logger.Debug("sshd: command exited", "error", waitErr)
	}

	// cmd.Wait() reaped the process and closed the pipes, but the
	// client-side relay is still blocked reading the session channel.
	// Exit closes it so the io.Copy above returns, then we join the relays.
	sess.ExitProcess(cmd.ProcessState)
	relay.Wait()
	return cmd.ProcessState
}

// buildEnv combines the target user's environment with the client-requested
// variables and SSH session metadata.
func (sess *session) buildEnv() []string {
	env := sysutil.CmdEnv(sess.sysUser, sess.shell)
	env = append(env, sess.env...)
	if sess.conn != nil {
		env = append(
			env,
			"SSH_CONNECTION="+sess.conn.RemoteAddr().String()+" "+sess.conn.LocalAddr().String(),
		)
	}
	if sess.ptmx != nil {
		env = append(env, "SSH_TTY="+sess.ptmx.Name())
	}
	if sess.agentSock != "" {
		env = append(env, "SSH_AUTH_SOCK="+sess.agentSock)
	}
	return env
}

func exitCodeOf(st *os.ProcessState) uint32 {
	if st == nil {
		return 1
	}
	if st.Exited() {
		return exitCodeToU32(st.ExitCode())
	}
	return 1
}

// exitCodeToU32 maps a process exit code to the SSH exit-status value.
// POSIX exit codes are 0-255. Anything out of range maps to 1.
func exitCodeToU32(code int) uint32 {
	if code < 0 || code > 255 {
		return 1
	}
	return uint32(code)
}
