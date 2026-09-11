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
	"uuid"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/ptysession"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// webSessionKeyIDPrefix marks control-plane user certificates for a web
// terminal session. Must stay in sync with the backend's mintSessionCert.
const webSessionKeyIDPrefix = "nokku:web:session:"

// session handles a single "session" channel.
type session struct {
	ssh.Channel

	server  *Server
	conn    *ssh.ServerConn
	st      *connState
	reqs    <-chan *ssh.Request
	sysUser *user.User
	shell   string

	// Exec'd commands use ctx, so a disconnect reaps them even if the
	// request stream misbehaves.
	ctx    context.Context
	cancel context.CancelFunc

	env     []string
	rawCmd  string
	handled bool

	sessionID string

	// agent forwarding listener, exported to the child as SSH_AUTH_SOCK
	agentLn   net.Listener
	agentSock string

	ptmx pty.Pty
	rec  *recording.Recorder

	exitMu sync.Mutex
	exited bool

	procMu   sync.Mutex
	proc     *os.Process
	wantKill bool

	// pendingSignals buffers signals that arrived before the command started,
	// flushed by setProc. Guarded by procMu.
	pendingSignals []os.Signal
}

// recOut feeds written bytes to the recorder before passing them on. Recorder
// methods swallow their errors, so a failing recording never disturbs the stream.
type recOut struct {
	w   io.Writer
	rec *recording.Recorder
}

// serveSessionChannel accepts a "session" channel and serves its request
// stream. Session caps are enforced before the channel is accepted.
func serveSessionChannel(
	s *Server,
	conn *ssh.ServerConn,
	st *connState,
	newCh ssh.NewChannel,
) (ch ssh.Channel) {
	defer s.recoverAndLog("channel session", func() {
		if ch != nil {
			_ = ch.Close()
			return
		}
		_ = newCh.Reject(ssh.ConnectionFailed, "channel handler failed")
	})

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

	c, reqs, err := newCh.Accept()
	if err != nil {
		s.logger.Debug("accept session channel failed", "error", err)
		return nil
	}
	ch = c
	s.serveSession(conn, st, c, reqs)
	return c
}

func (s *Server) serveSession(
	conn *ssh.ServerConn,
	st *connState,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
) {
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

	if loginErr := sysutil.LoginAllowed(sysUser, s.nologinFile); loginErr != nil {
		s.emit(eventWith(connEvent(conn), audit.EventAuthFailure, "", loginErr.Error()))
		s.authFailure(conn, loginErr)
		_ = ch.Close()
		return
	}

	sessionID := uuid.NewV7().String()
	ctx, cancel := context.WithCancel(context.Background())
	sess := &session{
		Channel:   ch,
		server:    s,
		conn:      conn,
		st:        st,
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

// handleRequests services the request stream, running shell/exec/subsystem
// work in a handler goroutine. On stream end the process is reaped and joined.
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

	// Client disconnected or the channel closed: reap the process, then wait
	// for the handler to wind down. Nothing to join if none ever started.
	sess.killProc()
	if started {
		<-handlerDone
	}
}

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

func (sess *session) forceCommand() string {
	if sess.conn == nil || sess.conn.Permissions == nil {
		return ""
	}
	return sess.conn.Permissions.Extensions["force-command"]
}

// webSession reports whether the session authenticated with a control-plane
// web-terminal certificate. The key id is signed, so it is trustworthy.
func (sess *session) webSession() bool {
	if sess.conn == nil || sess.conn.Permissions == nil {
		return false
	}
	return strings.HasPrefix(
		sess.conn.Permissions.Extensions["nokku-cert-key-id"],
		webSessionKeyIDPrefix,
	)
}

// acceptEnv is the client environment whitelist. A force-command refuses
// client env, so BASH_ENV or LD_PRELOAD cannot override a restricted command.
func (sess *session) acceptEnv(name string) bool {
	if sess.forceCommand() != "" {
		return false
	}
	// The recording label is only accepted from a web session, else a client
	// could label its recording with another session's id.
	if name == "NOKKU_SESSION_ID" {
		return sess.webSession()
	}
	return allowedEnv(name)
}

// allowedEnv admits only locale and terminal hints. PATH, LD_*, BASH_ENV, ENV
// and SSH_* are refused: they could steer program loading or shell startup.
func allowedEnv(name string) bool {
	switch name {
	case "TERM", "LANG", "TZ", "TERM_PROGRAM", "COLORTERM":
		return true
	// Reserved daemon metadata, no shell effect.
	case "NOKKU_SESSION_ID":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

// envValue returns the last value set for key, matching the child environment.
func (sess *session) envValue(key string) (string, bool) {
	kv := key + "="
	var value string
	found := false
	for _, e := range sess.env {
		if after, ok := strings.CutPrefix(e, kv); ok {
			value, found = after, true
		}
	}
	return value, found
}

// setEnv replaces any existing entry so the last-set value wins.
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
	if r.Name != sftpSubsystem {
		_ = req.Reply(false, nil)
		return "", false
	}
	sess.handled = true
	_ = req.Reply(true, nil)
	return r.Name, true
}

func (sess *session) runSubsystem(name string) uint32 {
	if name == sftpSubsystem {
		return sess.runSFTP()
	}
	return 1
}

// pty-req: string TERM, uint32 width, uint32 height, uint32 width_px,
// uint32 height_px, string modes.
func (sess *session) ptyReq(req *ssh.Request) {
	if !certExt(sess.conn, "permit-pty") {
		_ = req.Reply(false, nil)
		return
	}
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
		sess.server.logger.Debug("open pty failed", "error", err)
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

	sess.startRecorder(int(r.Width), int(r.Height))
	_ = req.Reply(true, nil)
}

// window-change: uint32 cols, uint32 rows, uint32 width_px, uint32 height_px.
func (sess *session) windowChange(req *ssh.Request) {
	var w struct{ Cols, Rows, W, H uint32 }
	if ssh.Unmarshal(req.Payload, &w) == nil && sess.ptmx != nil {
		if err := sess.ptmx.Resize(int(w.Cols), int(w.Rows)); err != nil {
			sess.server.logger.Debug("resize pty failed", "error", err)
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

// Exit reports the exit status and closes the channel. Idempotent, only the
// first call has an effect.
func (sess *session) Exit(code int) {
	sess.finish(code, func() {
		status := struct{ Status uint32 }{exitCodeToU32(code)}
		_, _ = sess.SendRequest("exit-status", false, ssh.Marshal(status))
	})
}

// ExitProcess reports a finished process like OpenSSH: exit-status normally,
// exit-signal when killed by a signal, so clients surface 128+signal.
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

// exitSignal sends an exit-signal channel request (RFC 4254 section 6.10).
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

// finish is the single teardown path: it emits the session_end audit event,
// delivers the terminal channel request via send, then closes the channel.
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

func (sess *session) run() {
	if sess.ptmx != nil {
		sess.runPTY()
		return
	}
	sess.runPlain()
}

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

// runPlain runs the command without a pty, the non-interactive `ssh host
// command` path.
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

	// Plain sessions record too: non-interactive exec is exactly where
	// sensitive output (cat, curl, git) leaves the machine.
	sess.startRecorder(80, 24)

	// Stderr goes to the extended data stream (like sshd), not the data
	// stream: length-prefixed protocols break if stderr bytes interleave.
	sess.runProcess(cmd, sess.Stderr())
}

// startRecorder builds the recorder when recording is on. No-op when off or
// one already exists (pty-req creates it earlier). width/height size the header.
func (sess *session) startRecorder(width, height int) {
	if sess.rec != nil || !sess.server.tun.Load().Record {
		return
	}
	// Only a canonical UUID is promoted from the reserved env: a free-form
	// value could forge another session's recording id.
	recSessionID := sess.sessionID
	if id, ok := sess.envValue("NOKKU_SESSION_ID"); ok && canonicalUUID(id) {
		recSessionID = id
	}
	var sink io.WriteCloser
	if sess.server.recordingSinkFactory != nil {
		// WithoutCancel: the upload stream must outlive the session
		// context, which is canceled while the session tears down.
		sink = sess.server.recordingSinkFactory(
			context.WithoutCancel(sess.ctx),
			recSessionID,
			sess.sysUser.Username,
		)
	}
	rec, err := recording.New(recording.Options{
		Width:     width,
		Height:    height,
		Title:     fmt.Sprintf("ssh-%s", sess.sysUser.Username),
		Label:     sess.sysUser.Username,
		SessionID: recSessionID,
		Sink:      sink,
	})
	if err == nil && rec != nil {
		sess.rec = rec
	}
}

// canonicalUUID reports whether s is a lowercase hyphenated 8-4-4-4-12 UUID,
// the form uuid.NewV7 produces. Re-serializing rejects braced and URN forms.
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

func (t recOut) Write(p []byte) (int, error) {
	t.rec.RecordOutput(p)
	return t.w.Write(p)
}

// runProcess relays the channel to cmd's stdin/stdout then reports the exit via
// ExitProcess. The caller configures cmd first. errW, if set, is the process stderr.
func (sess *session) runProcess(cmd *exec.Cmd, errW io.Writer) *os.ProcessState {
	if errW != nil {
		cmd.Stderr = errW
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		sess.server.logger.Debug("process stdin pipe failed", "error", err)
		sess.Exit(1)
		return nil
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		sess.server.logger.Debug("process stdout pipe failed", "error", err)
		sess.Exit(1)
		return nil
	}

	if err = cmd.Start(); err != nil {
		sess.server.logger.Debug("start command failed", "error", err)
		_ = stdin.Close()
		_ = stdout.Close()
		sess.Exit(1)
		return nil
	}
	sess.setProc(cmd.Process)

	var relay sync.WaitGroup

	// Only output is recorded on the plain path: without a PTY there is no
	// echo signal, so input cannot be told apart and is never captured.
	var outW io.Writer = sess
	if sess.rec != nil {
		outW = recOut{w: sess, rec: sess.rec}
	}

	relay.Go(func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	})

	// process -> client: only stdout, since length-prefixed protocols read
	// stderr as extended data.
	stdoutDone := make(chan struct{})
	relay.Go(func() {
		defer close(stdoutDone)
		_, _ = io.Copy(outW, stdout)
	})

	// Drain stdout before reaping. cmd.Wait() closes the stdout pipe,
	// which would truncate output the relay has not yet copied.
	<-stdoutDone
	if waitErr := cmd.Wait(); waitErr != nil {
		sess.server.logger.Debug("command exited", "error", waitErr)
	}

	// cmd.Wait() closed the pipes, but the client-side relay is still blocked
	// reading the channel. ExitProcess closes it, then the relays are joined.
	sess.ExitProcess(cmd.ProcessState)
	relay.Wait()
	return cmd.ProcessState
}

func (sess *session) buildEnv() []string {
	env := sysutil.CmdEnv(sess.sysUser, sess.shell)
	env = append(env, sess.env...)
	if sess.conn != nil {
		env = append(
			env,
			"SSH_CONNECTION="+connectionFields(sess.conn.RemoteAddr(), sess.conn.LocalAddr()),
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

// connectionFields renders the four SSH_CONNECTION fields (remote ip, remote
// port, local ip, local port). [net.Addr] alone would render host:port twice.
func connectionFields(remote, local net.Addr) string {
	rHost, rPort := splitHostPort(remote)
	lHost, lPort := splitHostPort(local)
	return rHost + " " + rPort + " " + lHost + " " + lPort
}

func splitHostPort(a net.Addr) (string, string) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), ""
	}
	return host, port
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

// exitCodeToU32 maps a process exit code to the SSH exit-status value. POSIX
// exit codes are 0-255, anything out of range maps to 1.
func exitCodeToU32(code int) uint32 {
	if code < 0 || code > 255 {
		return 1
	}
	return uint32(code)
}
