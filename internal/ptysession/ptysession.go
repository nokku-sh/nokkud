// Package ptysession runs a user's login shell inside a PTY and relays bytes
// between the PTY and the session transport, optionally recording the stream.
// It is shared by the embedded SSH server and the backend-relayed web
// terminal.
package ptysession

import (
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sync"

	"github.com/aymanbagabas/go-pty"

	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// Recorder records a session's input and output. A nil Recorder disables
// recording.
type Recorder interface {
	RecordOutput([]byte)
	RecordInput([]byte)
	Close()
}

// Configure prepares cmd to run sysUser's login shell. When command is empty
// the shell runs as a login shell; otherwise it runs `shell -c command`. The
// caller must already have built cmd attached to the PTY (via ptmx.Command)
// and supplies the environment. It returns the privilege-drop error from
// SysProcAttr when running as root.
func Configure(cmd *pty.Cmd, sysUser *user.User, shell, command string, env []string) error {
	cmd.Args[0] = "-" + filepath.Base(shell) // login shell
	if command != "" {
		cmd.Args = append(cmd.Args[:1], "-c", command)
	}
	cmd.Dir = sysUser.HomeDir
	cmd.Env = env

	attr, err := sysutil.SysProcAttr(sysUser)
	if err != nil {
		return err
	}
	cmd.SysProcAttr = attr
	return nil
}

// RunOptions configures a PTY session.
type RunOptions struct {
	// Pty is the already created and sized PTY the command runs in.
	Pty pty.Pty
	// Cmd is the command to run in Pty. It must have been built via
	// ptmx.Command and Configured with args, env, dir and privileges.
	Cmd *pty.Cmd
	// In is the client-to-process byte stream.
	In io.Reader
	// Out is the process-to-client byte stream.
	Out io.Writer
	// Rec records the session when non-nil. Input is recorded only while the
	// PTY has echo enabled (password prompts).
	Rec Recorder
	// OnStart, when set, is called with the process once it has started (used
	// to forward signals).
	OnStart func(*os.Process)
}

// Run starts Cmd in Pty and relays bytes between In/Out and the PTY until the
// child exits, then reaps it and returns its process state (nil when Start
// failed). The parent's copy of the PTY slave is closed so the master reports
// EOF as soon as the child exits.
//
// The returned waitInput joins the input relay goroutine. It must be called
// only after In has been closed, otherwise the relay is still blocked reading
// it; SSH sessions close the channel in ExitProcess before joining.
func Run(opts RunOptions) (ps *os.ProcessState, waitInput func()) {
	if err := opts.Cmd.Start(); err != nil {
		return nil, func() {}
	}
	if opts.OnStart != nil {
		opts.OnStart(opts.Cmd.Process)
	}
	closePTYSlave(opts.Pty)

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := opts.In.Read(buf)
			if n > 0 {
				if opts.Rec != nil && sysutil.EchoEnabled(opts.Pty.Fd()) {
					opts.Rec.RecordInput(buf[:n])
				}
				if _, werr := opts.Pty.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})

	out := opts.Out
	if opts.Rec != nil {
		out = &outputWriter{dst: opts.Out, rec: opts.Rec}
	}
	_, _ = io.Copy(out, opts.Pty)
	_ = opts.Pty.Close()
	_ = opts.Cmd.Wait()

	return opts.Cmd.ProcessState, wg.Wait
}

// outputWriter records output and forwards it to the transport.
type outputWriter struct {
	dst io.Writer
	rec Recorder
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.rec.RecordOutput(p)
	return w.dst.Write(p)
}

// closePTYSlave drops the parent's reference to the PTY slave so the master
// reports EOF once the child exits. No-op without a slave end.
func closePTYSlave(p pty.Pty) {
	if u, ok := p.(pty.UnixPty); ok {
		_ = u.Slave().Close()
	}
}
