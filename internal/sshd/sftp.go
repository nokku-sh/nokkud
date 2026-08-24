package sshd

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

	state := sess.runProcess(cmd, &slogWriter{log: sess.server.logger})
	return exitCodeOf(state)
}

// sftpServerCommand builds the `nokkud sftp-server` subprocess. Under the test
// binary the subcommand does not exist, so tests re-enter via the
// TestSFTPHelperProcess test.
func sftpServerCommand(ctx context.Context, home string) *exec.Cmd {
	bin := os.Args[0]
	args := []string{"sftp-server", home}
	if strings.HasSuffix(filepath.Base(bin), ".test") {
		args = []string{"-test.run=TestSFTPHelperProcess", "--", "sftp-server", home}
		// #nosec G702 - bin is the running process's own argv[0]. home is the
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
