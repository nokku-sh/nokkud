package sshd

import (
	"io"
	"os"
	"os/exec"

	"github.com/pkg/sftp"

	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// sftpServerCmd re-execs the daemon as the sftp-server. Tests swap it to
// re-enter the test binary.
var sftpServerCmd = func(home string) (*exec.Cmd, error) {
	// os.Executable, not argv[0]: the child runs as the target user, so the
	// binary must never be steerable through argv.
	bin, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// #nosec G204 - bin is this binary and home comes from the passwd entry.
	return exec.Command(bin, "sftp-server", home), nil
}

// ServeSFTP runs the SFTP protocol over stdin and stdout, rooted at home. It
// runs as the target user, so the OS permissions bound what it can touch.
func ServeSFTP(home string) error {
	rw := struct {
		io.Reader
		io.WriteCloser
	}{os.Stdin, os.Stdout}
	srv, err := sftp.NewServer(rw, sftp.WithServerWorkingDirectory(home))
	if err != nil {
		return err
	}
	defer srv.Close()
	return srv.Serve()
}

func (sess *session) runSFTP() {
	home := sess.sysUser.HomeDir
	cmd, err := sftpServerCmd(home)
	if err != nil {
		sess.Exit(1)
		return
	}
	attr, err := sysutil.SysProcAttr(sess.sysUser)
	if err != nil {
		sess.Exit(1)
		return
	}
	cmd.SysProcAttr = attr
	cmd.Dir = home
	sess.runProcess(cmd)
}
