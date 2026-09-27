package sshd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"uuid"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// webSessionKeyIDPrefix marks control-plane user certificates for a web
// terminal session. Must stay in sync with the backend's mintSessionCert.
const webSessionKeyIDPrefix = "nokku:web:session:"

// maxClientEnv caps env requests per session.
const maxClientEnv = 64

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

func (s *Server) serveSession(st *connState, newCh ssh.NewChannel) {
	conn := st.conn
	ch, reqs, err := newCh.Accept()
	if err != nil {
		slog.Debug("accept session channel failed", "error", err)
		return
	}
	defer ch.Close()

	sysUser, err := sysutil.LookupUser(conn.User())
	if err == nil {
		err = sysutil.LoginAllowed(sysUser, s.nologinFile)
	}
	if err != nil {
		_ = s.deny(conn, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
		sessionID: uuid.NewV7().String(),
	}
	s.audit.Emit(sess.event(audit.EventSessionStart))
	sess.handleRequests()
}

func (sess *session) event(typ audit.EventType) audit.Event {
	ev := connEvent(sess.conn, typ)
	ev.SessionID = sess.sessionID
	ev.User = sess.sysUser.Username
	return ev
}

// handleRequests serves the request stream and runs shell, exec or subsystem
// work in one handler goroutine. When the stream ends the process is killed
// and the handler joined.
func (sess *session) handleRequests() {
	var handlerDone chan struct{}
	startHandler := func(fn func()) {
		handlerDone = make(chan struct{})
		go func() {
			defer close(handlerDone)
			defer recoverPanic("session handler")
			fn()
		}()
	}

	for req := range sess.reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handleCommand(req) {
				startHandler(sess.run)
			}
		case "subsystem":
			if sess.acceptSubsystem(req) {
				startHandler(sess.runSFTP)
			}
		case "env":
			_ = req.Reply(sess.setClientEnv(req.Payload), nil)
		case "pty-req":
			sess.ptyReq(req)
		case agentRequestType:
			if sess.agentRequest(req) {
				go sess.serveAgent()
			}
		case "window-change":
			sess.windowChange(req)
		case "signal":
			sess.signal(req)
		default:
			_ = req.Reply(false, nil)
		}
	}

	sess.killProc()
	if handlerDone != nil {
		<-handlerDone
		return
	}
	// No command ever ran, so nothing else releases what pty-req opened.
	if sess.ptmx != nil {
		_ = sess.ptmx.Close()
	}
	if sess.rec != nil {
		sess.rec.Close()
	}
}

func (sess *session) handleCommand(req *ssh.Request) bool {
	if sess.handled {
		_ = req.Reply(false, nil)
		return false
	}
	// A force-command replaces whatever the client asked for, like sshd.
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

	ev := sess.event(audit.EventCommand)
	ev.Command = sess.rawCmd
	sess.server.audit.Emit(ev)
	return true
}

func (sess *session) forceCommand() string {
	return sess.conn.Permissions.Extensions["force-command"]
}

// webSession reports whether the session logged in with a control-plane web
// terminal cert. The key id is signed by the CA, so it is trustworthy.
func (sess *session) webSession() bool {
	return strings.HasPrefix(sess.conn.Permissions.Extensions["nokku-cert-key-id"], webSessionKeyIDPrefix)
}

// setClientEnv applies an env request if the whitelist admits it. A
// force-command refuses all client env, so BASH_ENV or LD_PRELOAD cannot
// bend a restricted command.
func (sess *session) setClientEnv(payload []byte) bool {
	var e struct{ Name, Value string }
	if sess.handled || len(sess.env) >= maxClientEnv || sess.forceCommand() != "" ||
		ssh.Unmarshal(payload, &e) != nil {
		return false
	}
	// Only a web session may label its recording, else a client could claim
	// another session's recording id.
	if e.Name == "NOKKU_SESSION_ID" && !sess.webSession() {
		return false
	}
	if !allowedEnv(e.Name) {
		return false
	}
	sess.setEnv(e.Name, e.Value)
	return true
}

// allowedEnv admits only locale and terminal hints. PATH, LD_*, BASH_ENV, ENV
// and SSH_* could steer program loading or shell startup.
func allowedEnv(name string) bool {
	switch name {
	case "TERM", "LANG", "TZ", "TERM_PROGRAM", "COLORTERM", "NOKKU_SESSION_ID":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

// envValue returns the value set for key, if any.
func (sess *session) envValue(key string) (string, bool) {
	for _, e := range sess.env {
		if v, ok := strings.CutPrefix(e, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// setEnv replaces an existing entry, so each key appears once.
func (sess *session) setEnv(key, value string) {
	kv := key + "=" + value
	for i, e := range sess.env {
		if strings.HasPrefix(e, key+"=") {
			sess.env[i] = kv
			return
		}
	}
	sess.env = append(sess.env, kv)
}

func (sess *session) acceptSubsystem(req *ssh.Request) bool {
	var r struct{ Name string }
	// A force-command takes precedence over subsystems, like sshd.
	ok := !sess.handled && sess.forceCommand() == "" &&
		ssh.Unmarshal(req.Payload, &r) == nil && r.Name == "sftp"
	sess.handled = sess.handled || ok
	_ = req.Reply(ok, nil)
	if ok {
		ev := sess.event(audit.EventSubsystem)
		ev.Command = r.Name
		sess.server.audit.Emit(ev)
	}
	return ok
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
	if sess.handled || sess.ptmx != nil || !certExt(sess.conn, "permit-pty") ||
		ssh.Unmarshal(req.Payload, &r) != nil {
		_ = req.Reply(false, nil)
		return
	}
	ptmx, err := pty.New()
	if err != nil {
		slog.Debug("open pty failed", "error", err)
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
			slog.Debug("resize pty failed", "error", err)
		} else {
			sess.rec.RecordResize(int(w.Cols), int(w.Rows))
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

	ev := sess.event(audit.EventSessionEnd)
	ev.ExitCode = code
	sess.server.audit.Emit(ev)

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

// runPTY runs the login shell, or the command, in the session's pty and
// relays bytes until it exits.
func (sess *session) runPTY() {
	cmd := sess.ptmx.Command(sess.shell)
	cmd.Args[0] = "-" + filepath.Base(sess.shell) // login shell
	if sess.rawCmd != "" {
		cmd.Args = append(cmd.Args[:1], "-c", sess.rawCmd)
	}
	cmd.Dir = sess.sysUser.HomeDir
	cmd.Env = sess.buildEnv()
	attr, err := sysutil.SysProcAttr(sess.sysUser)
	if err != nil {
		sess.Exit(1)
		return
	}
	cmd.SysProcAttr = attr
	if err = cmd.Start(); err != nil {
		slog.Debug("start pty command failed", "error", err)
		sess.Exit(1)
		return
	}
	sess.setProc(cmd.Process)
	// Drop our slave end, so the master reports EOF once the child exits.
	if u, ok := sess.ptmx.(pty.UnixPty); ok {
		_ = u.Slave().Close()
	}

	var input sync.WaitGroup
	input.Go(func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := sess.Read(buf)
			if n > 0 {
				// Only echoed input is recorded, so password prompts never are.
				if sess.rec != nil && sysutil.EchoEnabled(sess.ptmx.Fd()) {
					sess.rec.RecordInput(buf[:n])
				}
				if _, writeErr := sess.ptmx.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	})

	var out io.Writer = sess
	if sess.rec != nil {
		out = recOut{w: sess, rec: sess.rec}
	}
	_, _ = io.Copy(out, sess.ptmx)
	_ = sess.ptmx.Close()
	_ = cmd.Wait()

	// ExitProcess closes the channel, which unblocks the input relay.
	sess.ExitProcess(cmd.ProcessState)
	input.Wait()
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

	// Stderr goes to the extended data stream like sshd. Length-prefixed
	// protocols break if stderr bytes interleave with stdout.
	cmd.Stderr = sess.Stderr()
	sess.runProcess(cmd)
}

// startRecorder builds the recorder when recording is on. No-op when off or
// one already exists (pty-req creates it earlier). width/height size the header.
func (sess *session) startRecorder(width, height int) {
	if sess.rec != nil || !sess.server.policy.Load().Record {
		return
	}
	// Only a canonical UUID is promoted from the reserved env: a free-form
	// value could forge another session's recording id.
	recSessionID := sess.sessionID
	if id, ok := sess.envValue("NOKKU_SESSION_ID"); ok && canonicalUUID(id) {
		recSessionID = id
	}
	var sink io.WriteCloser
	if sess.server.recordingSink != nil {
		// WithoutCancel: the upload stream must outlive the session
		// context, which is canceled while the session tears down.
		sink = sess.server.recordingSink(
			context.WithoutCancel(sess.ctx),
			recSessionID,
			sess.sysUser.Username,
		)
	}
	term, _ := sess.envValue("TERM")
	rec, err := recording.New(recording.Options{
		Width:     width,
		Height:    height,
		Title:     fmt.Sprintf("ssh-%s", sess.sysUser.Username),
		Label:     sess.sysUser.Username,
		SessionID: recSessionID,
		User:      sess.sysUser.Username,
		Term:      term,
		Sink:      sink,
		OnLimit:   func() { sess.recordingDegraded("size limit reached, rest of the session not recorded") },
	})
	if err != nil {
		// Recording fails open so a full disk never locks admins out, but
		// the gap is always on the audit trail.
		slog.Warn("session not recorded", "session_id", sess.sessionID, "error", err)
		if sink != nil {
			_ = sink.Close()
		}
		sess.recordingDegraded("not recorded: " + err.Error())
		return
	}
	sess.rec = rec
}

func (sess *session) recordingDegraded(reason string) {
	ev := sess.event(audit.EventRecordingDegraded)
	ev.Error = reason
	sess.server.audit.Emit(ev)
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

// runProcess relays the channel to cmd's stdin and stdout, then reports the
// exit. The caller configures cmd first.
func (sess *session) runProcess(cmd *exec.Cmd) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		slog.Debug("process stdin pipe failed", "error", err)
		sess.Exit(1)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		slog.Debug("process stdout pipe failed", "error", err)
		sess.Exit(1)
		return
	}

	if err = cmd.Start(); err != nil {
		slog.Debug("start command failed", "error", err)
		_ = stdin.Close()
		_ = stdout.Close()
		sess.Exit(1)
		return
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
		slog.Debug("command exited", "error", waitErr)
	}

	// cmd.Wait() closed the pipes, but the client-side relay is still blocked
	// reading the channel. ExitProcess closes it, then the relays are joined.
	sess.ExitProcess(cmd.ProcessState)
	relay.Wait()
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
