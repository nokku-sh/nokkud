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

// sftpSubsystem is the subsystem name scp and sftp request.
const sftpSubsystem = "sftp"

type stdioConn struct {
	in  io.Reader
	out io.Writer
}

type slogWriter struct {
	log *slog.Logger
}

func (c *stdioConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *stdioConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *stdioConn) Close() error                { return nil }

func (w *slogWriter) Write(p []byte) (int, error) {
	w.log.Debug("sftp-server stderr", "line", string(p))
	return len(p), nil
}

// ServeSFTP runs the SFTP protocol over stdin/stdout, rooted at home. It runs
// as the target user, so access is bounded by that user's OS permissions.
func ServeSFTP(home string) error {
	conn := &stdioConn{in: os.Stdin, out: os.Stdout}
	srv, err := sftp.NewServer(conn, sftp.WithServerWorkingDirectory(home))
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Serve()
}

func (sess *session) runSFTP() uint32 {
	home := sess.sysUser.HomeDir

	cmd := sftpServerCommand(context.Background(), home)
	attr, err := sysutil.SysProcAttr(sess.sysUser)
	if err != nil {
		sess.server.logger.Debug("resolve sftp sysproc attrs failed", "error", err)
		return 1
	}
	cmd.SysProcAttr = attr
	cmd.Dir = home

	state := sess.runProcess(cmd, &slogWriter{log: sess.server.logger})
	return exitCodeOf(state)
}

// sftpServerCommand builds the sftp-server subprocess, re-entering via
// TestSFTPHelperProcess when running under the test binary.
func sftpServerCommand(ctx context.Context, home string) *exec.Cmd {
	// os.Executable, not argv[0]: the re-exec runs as the target user, so it
	// must never be steerable by the daemon's argv[0].
	bin, err := os.Executable()
	if err != nil {
		bin = os.Args[0]
	}
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
