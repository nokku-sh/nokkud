package sshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"uuid"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/recording"
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
	sysUser *account
	// The certificate principal auth matched, reported with the recording.
	principal string

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

	// The pty master and its slave end, opened by pty-req.
	ptmx, tty *os.File

	rec *recording.Recorder

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
// methods swallow their errors, so a failing recording never disturbs the
// stream. A nil recorder records nothing.
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &session{
		Channel:   ch,
		server:    s,
		conn:      conn,
		st:        st,
		reqs:      reqs,
		sysUser:   st.user,
		principal: st.principal,
		ctx:       ctx,
		cancel:    cancel,
		sessionID: uuid.NewV7().String(),
	}
	s.emit(sess.event(eventSessionStart))
	sess.handleRequests()
}

func (sess *session) event(typ eventType) auditEvent {
	ev := connEvent(sess.conn, typ)
	ev.SessionID = sess.sessionID
	ev.User = sess.sysUser.Name
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

	// The client is gone, so stop waiting on output a background process may
	// still hold open.
	sess.cancel()
	sess.killProc()
	if handlerDone != nil {
		<-handlerDone
		return
	}
	// No command ever ran, so nothing else releases what pty-req opened.
	if sess.ptmx != nil {
		_ = sess.ptmx.Close()
		_ = sess.tty.Close()
	}
	sess.rec.Close()
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

	ev := sess.event(eventCommand)
	ev.Command = sess.rawCmd
	sess.server.emit(ev)
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
		ev := sess.event(eventSubsystem)
		ev.Command = r.Name
		sess.server.emit(ev)
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
	ptmx, tty, err := openPTY()
	if err != nil {
		slog.Debug("open pty failed", "error", err)
		_ = req.Reply(false, nil)
		return
	}
	if err = setWinsize(ptmx, r.Width, r.Height); err != nil {
		_ = ptmx.Close()
		_ = tty.Close()
		_ = req.Reply(false, nil)
		return
	}
	// The daemon opened the pty as root. The user has to own it, like under
	// OpenSSH, or opening the tty by its path is denied.
	if os.Geteuid() == 0 {
		if err = tty.Chown(int(sess.sysUser.UID), -1); err != nil {
			slog.Debug("chown pty failed", "error", err)
		}
	}
	sess.ptmx, sess.tty = ptmx, tty
	// A client without TERM sends an empty one, buildEnv then sets the default.
	if r.Term != "" {
		sess.setEnv("TERM", r.Term)
	}
	sess.startRecorder(int(r.Width), int(r.Height))
	_ = req.Reply(true, nil)
}

// window-change: uint32 cols, uint32 rows, uint32 width_px, uint32 height_px.
func (sess *session) windowChange(req *ssh.Request) {
	var w struct{ Cols, Rows, W, H uint32 }
	if ssh.Unmarshal(req.Payload, &w) == nil && sess.ptmx != nil {
		if err := setWinsize(sess.ptmx, w.Cols, w.Rows); err != nil {
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

// exit reports the exit status and closes the channel. Idempotent, only the
// first call has an effect.
func (sess *session) exit(code int) {
	sess.finish(code, func() {
		status := struct{ Status uint32 }{exitCodeToU32(code)}
		_, _ = sess.SendRequest("exit-status", false, ssh.Marshal(status))
	})
}

// exitProcess reports a finished process like OpenSSH: exit-status normally,
// exit-signal when killed by a signal, so clients surface 128+signal.
func (sess *session) exitProcess(st *os.ProcessState) {
	name, code, signaled := processSignal(st)
	if !signaled {
		status := 1
		if st != nil && st.Exited() {
			status = st.ExitCode()
		}
		sess.exit(status)
		return
	}
	if name == "" {
		// Signal outside the RFC 4254 name table: still surface 128+n.
		sess.exit(code)
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

	sess.rec.RecordExit(code)
	sess.rec.Close()

	ev := sess.event(eventSessionEnd)
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

// shellCmd builds the session's process the way OpenSSH starts it. A shell
// request gets a login shell, argv[0] with a dash, so the profile is read. A
// command runs as "shell -c command" under the shell's plain name.
func (sess *session) shellCmd() (*exec.Cmd, error) {
	shell := sess.sysUser.Shell
	// #nosec G204 - running the authenticated user's shell is the SSH
	// server's purpose. The process is spawned with that user's privileges.
	cmd := exec.CommandContext(sess.ctx, shell)
	cmd.Args = []string{"-" + filepath.Base(shell)}
	if sess.rawCmd != "" {
		cmd.Args = []string{filepath.Base(shell), "-c", sess.rawCmd}
	}
	cmd.Dir = sess.sysUser.Home
	cmd.Env = sess.buildEnv()
	attr, err := sysProcAttr(sess.sysUser)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = attr
	return cmd, nil
}

// startInHome starts the session's process in the user's home. The chdir
// happens in the child after the credential drop, so only a failed start
// shows that the user cannot enter it. Like sshd, the process then runs in /
// and the caller prints the returned notice.
func (sess *session) startInHome(start func(*exec.Cmd) error) (cmd *exec.Cmd, notice string, err error) {
	if cmd, err = sess.shellCmd(); err != nil {
		return nil, "", err
	}
	if err = start(cmd); err == nil {
		return cmd, "", nil
	}
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return nil, "", err
	}
	retry, retryErr := sess.shellCmd()
	if retryErr != nil {
		return nil, "", err
	}
	retry.Dir = "/"
	if start(retry) != nil {
		return nil, "", err
	}
	reason := errno.Error()
	return retry, fmt.Sprintf(
		"Could not chdir to home directory %s: %s%s",
		sess.sysUser.Home, strings.ToUpper(reason[:1]), reason[1:],
	), nil
}

// runPTY runs the shell or the command in the session's pty and relays bytes
// until it exits.
func (sess *session) runPTY() {
	defer sess.ptmx.Close()
	defer sess.tty.Close()

	cmd, notice, err := sess.startInHome(func(cmd *exec.Cmd) error {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = sess.tty, sess.tty, sess.tty
		// The pty becomes the controlling terminal of the new session.
		cmd.SysProcAttr.Setctty = true
		return cmd.Start()
	})
	if err != nil {
		slog.Debug("start pty command failed", "error", err)
		sess.exit(1)
		return
	}
	sess.setProc(cmd.Process)
	// Drop our slave end, so the master reports EOF once the child exits.
	_ = sess.tty.Close()
	// A background process can keep the slave open after the client is gone.
	// Closing the master hangs it up, as sshd does when a connection ends.
	stop := context.AfterFunc(sess.ctx, func() { _ = sess.ptmx.Close() })
	defer stop()

	var input sync.WaitGroup
	input.Go(func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := sess.Read(buf)
			if n > 0 {
				// Only echoed input is recorded, so password prompts never are.
				if sess.rec != nil && echoEnabled(sess.ptmx) {
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

	out := recOut{w: sess, rec: sess.rec}
	if notice != "" {
		_, _ = io.WriteString(out, notice+"\r\n")
	}
	_, _ = io.Copy(out, sess.ptmx)
	_ = sess.ptmx.Close()
	_ = cmd.Wait()

	// exitProcess closes the channel, which unblocks the input relay.
	sess.exitProcess(cmd.ProcessState)
	input.Wait()
}

// runPlain runs the shell or the command without a pty, the non-interactive
// `ssh host command` path.
func (sess *session) runPlain() {
	// Plain sessions record too: non-interactive exec is exactly where
	// sensitive output (cat, curl, git) leaves the machine.
	sess.startRecorder(80, 24)

	var stdin io.WriteCloser
	var stdout io.ReadCloser
	cmd, notice, err := sess.startInHome(func(cmd *exec.Cmd) (err error) {
		// Stderr goes to the extended data stream like sshd. Length-prefixed
		// protocols break if stderr bytes interleave with stdout.
		cmd.Stderr = recOut{w: sess.Stderr(), rec: sess.rec}
		stdin, stdout, err = startPiped(cmd)
		return err
	})
	if err != nil {
		slog.Debug("start command failed", "error", err)
		sess.exit(1)
		return
	}
	if notice != "" {
		_, _ = io.WriteString(sess.Stderr(), notice+"\n")
	}
	sess.relay(cmd, stdin, stdout)
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
			sess.sysUser.Name,
			sess.principal,
		)
	}
	term, _ := sess.envValue("TERM")
	rec, err := recording.New(recording.Options{
		Width:     width,
		Height:    height,
		Title:     "ssh-" + sess.sysUser.Name,
		SessionID: recSessionID,
		User:      sess.sysUser.Name,
		Principal: sess.principal,
		Term:      term,
		Sink:      sink,
		OnLimit:   sess.recordingFull,
		MaxSize:   sess.server.maxRecording,
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

// recordingFull ends the session at the recording's size limit, so nothing
// runs unrecorded and flooding output cannot switch recording off.
func (sess *session) recordingFull() {
	sess.recordingDegraded("size limit reached, session ended")
	notice := "nokkud: the recording of this session is full, closing it"
	if sess.ptmx != nil {
		_, _ = io.WriteString(sess, "\r\n"+notice+"\r\n")
	} else {
		_, _ = io.WriteString(sess.Stderr(), notice+"\n")
	}
	sess.exit(1)
}

func (sess *session) recordingDegraded(reason string) {
	ev := sess.event(eventRecordingDegraded)
	ev.Error = reason
	sess.server.emit(ev)
}

// canonicalUUID reports whether s is a lowercase hyphenated 8-4-4-4-12 UUID,
// the form [uuid.NewV7] produces. Re-serializing rejects braced and URN forms.
func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

func (t recOut) Write(p []byte) (int, error) {
	t.rec.RecordOutput(p)
	return t.w.Write(p)
}

// startPiped starts cmd with pipes on stdin and stdout. A failed start closes
// both.
func startPiped(cmd *exec.Cmd) (stdin io.WriteCloser, stdout io.ReadCloser, err error) {
	if stdin, err = cmd.StdinPipe(); err != nil {
		return nil, nil, err
	}
	if stdout, err = cmd.StdoutPipe(); err != nil {
		_ = stdin.Close()
		return nil, nil, err
	}
	// Bounds Wait when a background process keeps stderr open.
	cmd.WaitDelay = time.Second
	return stdin, stdout, cmd.Start()
}

// relay copies between the channel and the started cmd's pipes, then reports
// the exit.
func (sess *session) relay(cmd *exec.Cmd, stdin io.WriteCloser, stdout io.ReadCloser) {
	sess.setProc(cmd.Process)
	stop := context.AfterFunc(sess.ctx, func() { _ = stdout.Close() })
	defer stop()

	var relay sync.WaitGroup

	// Only output is recorded on the plain path: without a PTY there is no
	// echo signal, so input cannot be told apart and is never captured.
	outW := recOut{w: sess, rec: sess.rec}

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
	// reading the channel. exitProcess closes it, then the relays are joined.
	sess.exitProcess(cmd.ProcessState)
	relay.Wait()
}

func (sess *session) buildEnv() []string {
	env := cmdEnv(sess.sysUser)
	env = append(env, sess.env...)
	if sess.conn != nil {
		// The same two variables sshd sets. bash only reads ~/.bashrc for a
		// remote command when it sees SSH_CLIENT.
		rHost, rPort := splitHostPort(sess.conn.RemoteAddr())
		lHost, lPort := splitHostPort(sess.conn.LocalAddr())
		env = append(
			env,
			"SSH_CLIENT="+rHost+" "+rPort+" "+lPort,
			"SSH_CONNECTION="+rHost+" "+rPort+" "+lHost+" "+lPort,
		)
	}
	if sess.ptmx != nil {
		env = append(env, "SSH_TTY="+sess.tty.Name())
		// Like sshd, only a pty session has a TERM.
		if _, ok := sess.envValue("TERM"); !ok {
			env = append(env, "TERM=xterm-256color")
		}
	}
	if sess.agentSock != "" {
		env = append(env, "SSH_AUTH_SOCK="+sess.agentSock)
	}
	return env
}

func splitHostPort(a net.Addr) (string, string) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), ""
	}
	return host, port
}

// exitCodeToU32 maps a process exit code to the SSH exit-status value. POSIX
// exit codes are 0-255, anything out of range maps to 1.
func exitCodeToU32(code int) uint32 {
	if code < 0 || code > 255 {
		return 1
	}
	return uint32(code)
}
