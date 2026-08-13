package sshd

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/sftp"

	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// sftpSubsystem is the SSH subsystem name that scp -s and sftp use for the
// SFTP protocol.
const sftpSubsystem = "sftp"

// ServeSFTP runs the SFTP protocol over [os.Stdin]/[os.Stdout], rooted at
// home. It is spawned by the server as the target user, so file access is
// bounded by that user's OS permissions (matching sshd's sftp-server).
func ServeSFTP(home string) error {
	conn := &stdioConn{in: os.Stdin, out: os.Stdout}
	srv, err := sftp.NewServer(conn, sftp.WithServerWorkingDirectory(home))
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Serve()
}

// stdioConn adapts stdin/stdout into the [io.ReadWriteCloser] pkg/sftp wants.
type stdioConn struct {
	in  io.Reader
	out io.Writer
}

func (c *stdioConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *stdioConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *stdioConn) Close() error                { return nil }

// runSFTP serves the SFTP subsystem for this session and returns the exit
// status. The SFTP protocol runs in a child process dropped to the target
// user's privileges, with the session channel relayed to its stdin/stdout.
func (sess *session) runSFTP() uint32 {
	home := sess.sysUser.HomeDir

	cmd := sftpServerCommand(context.Background(), home)
	attr, err := sysutil.SysProcAttr(sess.sysUser)
	if err != nil {
		sess.server.logger.Debug("sshd: sftp sysproc", "error", err)
		return 1
	}
	cmd.SysProcAttr = attr
	cmd.Dir = home

	stdin, err := cmd.StdinPipe()
	if err != nil {
		sess.server.logger.Debug("sshd: sftp stdin pipe", "error", err)
		return 1
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		sess.server.logger.Debug("sshd: sftp stdout pipe", "error", err)
		return 1
	}
	cmd.Stderr = &slogWriter{log: sess.server.logger}

	if err = cmd.Start(); err != nil {
		sess.server.logger.Debug("sshd: start sftp", "error", err)
		_ = stdin.Close()
		_ = stdout.Close()
		return 1
	}
	sess.setProc(cmd.Process)

	var wg sync.WaitGroup

	// client -> sftp-server
	wg.Go(func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	})

	// sftp-server -> client
	stdoutDone := make(chan struct{})
	wg.Go(func() {
		defer close(stdoutDone)
		_, _ = io.Copy(sess, stdout)
	})

	// Drain stdout before reaping: cmd.Wait() closes the stdout pipe, which
	// would truncate any output the relay has not yet copied.
	<-stdoutDone
	_ = cmd.Wait()
	code := exitCodeOf(cmd.ProcessState)

	// Exit closes the session channel, which unblocks both relays above;
	// join them so no goroutine outlives the session.
	sess.ExitProcess(cmd.ProcessState)
	wg.Wait()
	return code
}

// sftpServerCommand builds the `nokkud sftp-server` subprocess. Under the test
// binary the subcommand does not exist, so tests re-enter via the
// TestSFTPHelperProcess test.
func sftpServerCommand(ctx context.Context, home string) *exec.Cmd {
	bin := os.Args[0]
	args := []string{"sftp-server", home}
	if strings.HasSuffix(filepath.Base(bin), ".test") {
		args = []string{"-test.run=TestSFTPHelperProcess", "--", "sftp-server", home}
		// #nosec G702 - bin is the running process's own argv[0]; home is the
		// authenticated user's home directory, not attacker input.
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "GO_WANT_SFTP_HELPER_PROCESS=1")
		return cmd
	}
	// #nosec G702 - see above.
	return exec.CommandContext(ctx, bin, args...)
}

// slogWriter routes a subprocess's stderr into the structured logger.
type slogWriter struct {
	log *slog.Logger
}

func (w *slogWriter) Write(p []byte) (int, error) {
	w.log.Debug("sshd: sftp-server stderr", "line", string(p))
	return len(p), nil
}
