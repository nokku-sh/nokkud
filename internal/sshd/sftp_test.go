package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// TestSFTPHelperProcess re-enters the test binary as the sftp-server
// subprocess. It is spawned by the server under the `--` convention. See
// sftpServerCommand.
func TestSFTPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SFTP_HELPER_PROCESS") != "1" {
		return
	}
	t.Log("sftp-server helper")
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) != 2 || args[0] != "sftp-server" {
		fmt.Fprintln(os.Stderr, "bad helper args:", args)
		os.Exit(2)
	}
	if err := ServeSFTP(args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "sftp-server:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// sftpClient dials a fresh server connection and returns an SFTP client. The
// SFTP server roots at the target user's real home directory (like sshd), so
// tests create a scratch subdirectory under it and use absolute paths.
func sftpClient(t *testing.T, ca testCA) (*sftp.Client, func()) {
	t.Helper()
	addr, closeFn := startTestServer(t, ca)

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		closeFn()
		t.Fatalf("dial: %v", err)
	}

	sc, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		closeFn()
		t.Fatalf("sftp client: %v", err)
	}
	return sc, func() {
		sc.Close()
		client.Close()
		closeFn()
	}
}

// homeScratch creates a unique directory under the target user's real home,
// which is where the SFTP server roots. Absolute paths are used throughout so
// operations land in the scratch dir and are cleaned up afterwards.
func homeScratch(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	//nolint:usetesting // must live under the real home. t.TempDir() is /tmp
	dir, err := os.MkdirTemp(cur.HomeDir, ".nokkud-sftp-test-*")
	if err != nil {
		t.Fatalf("scratch dir under %s: %v", cur.HomeDir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestServerSFTPTransfer(t *testing.T) {
	ca := newTestCA(t)
	scratch := homeScratch(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	// Write a file, read it back, list the directory.
	payload := []byte("hello nokkud sftp")
	path := filepath.Join(scratch, "hello.txt")
	f, err := sc.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err = f.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("contents = %q, want %q", got, payload)
	}

	r, err := sc.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = r.Close()
	if !bytes.Equal(data, payload) {
		t.Fatalf("read via client = %q, want %q", data, payload)
	}

	entries, err := sc.ReadDir(scratch)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "hello.txt" {
		t.Fatalf("readdir = %+v, want exactly hello.txt", entries)
	}
}

func TestServerSFTPOps(t *testing.T) {
	ca := newTestCA(t)
	scratch := homeScratch(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	// mkdir/rename/remove/stat round-trip.
	if err := sc.Mkdir(filepath.Join(scratch, "sub")); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := sc.Rename(
		filepath.Join(scratch, "sub"),
		filepath.Join(scratch, "renamed"),
	); err != nil {
		t.Fatalf("rename: %v", err)
	}
	info, err := sc.Stat(filepath.Join(scratch, "renamed"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("stat: expected directory, got %v", info.Mode())
	}
	if err = sc.RemoveDirectory(filepath.Join(scratch, "renamed")); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if _, err = sc.Stat(filepath.Join(scratch, "renamed")); err == nil {
		t.Fatal("expected stat to fail after rmdir")
	}
}

// TestServerSFTPWorkingDir verifies relative paths resolve under the user's
// real home directory, like sshd's sftp-server.
func TestServerSFTPWorkingDir(t *testing.T) {
	ca := newTestCA(t)
	home := currentHome(t)
	sc, closeFn := sftpClient(t, ca)
	defer closeFn()

	wd, err := sc.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if wd != home {
		t.Fatalf("working dir = %q, want %q", wd, home)
	}

	// A relative path must resolve under home.
	if err = sc.Mkdir("nokkud-rel-test"); err != nil {
		t.Fatalf("mkdir relative: %v", err)
	}
	defer func() { _ = os.RemoveAll(filepath.Join(home, "nokkud-rel-test")) }()
	if _, err = os.Stat(filepath.Join(home, "nokkud-rel-test")); err != nil {
		t.Fatalf("relative dir not created under home: %v", err)
	}
}

// TestServerSCPModern drives the real scp binary in SFTP mode (scp -s), which
// speaks the SFTP protocol through the sftp subsystem.
func TestServerSCPModern(t *testing.T) {
	scp, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("scp not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerSCPModern requires running under the test binary")
	}

	ca := newTestCA(t)
	scratch := homeScratch(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	payload := []byte("scp modern mode\n")
	src := filepath.Join(t.TempDir(), "in.txt")
	if err = os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	host, port := hostPort(t, addr)
	user := currentUser(t)
	dst := fmt.Sprintf("%s@%s:%s", user, host, filepath.Join(scratch, "copied.txt"))

	cmd := exec.Command(
		scp,
		"-s",
		"-P", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-i", userCertFile(t, ca),
		src,
		dst,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scp failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(filepath.Join(scratch, "copied.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("copied contents = %q, want %q", got, payload)
	}
}

// TestServerRsync drives the real rsync binary over the embedded server's
// exec path (rsync --server), which is how `rsync user@host:src dst` works.
func TestServerRsync(t *testing.T) {
	rsync, err := exec.LookPath("rsync")
	if err != nil {
		t.Skip("rsync not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerRsync requires running under the test binary")
	}

	ca := newTestCA(t)
	scratch := homeScratch(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	payload := []byte("rsync over nokkud\n")
	src := filepath.Join(t.TempDir(), "data.txt")
	if err = os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	host, port := hostPort(t, addr)
	user := currentUser(t)
	remote := fmt.Sprintf("%s@%s:%s", user, host, filepath.Join(scratch, "data.txt"))
	sshOpts := fmt.Sprintf(
		"ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		port,
		userCertFile(t, ca),
	)

	cmd := exec.Command(
		rsync,
		"-e", sshOpts,
		src,
		remote,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rsync failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(filepath.Join(scratch, "data.txt"))
	if err != nil {
		t.Fatalf("read rsynced file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("rsynced contents = %q, want %q", got, payload)
	}
}

// TestServerGit drives git over the embedded server: git speaks the pack
// protocol through `exec git-receive-pack` on a session channel.
func TestServerGit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	if !isTestBinary() {
		t.Fatal("TestServerGit requires running under the test binary")
	}

	ca := newTestCA(t)
	scratch := homeScratch(t)
	repo := filepath.Join(scratch, "repo.git")
	if err = os.MkdirAll(repo, 0o700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	cmd := exec.Command(git, "init", "--bare", repo)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	host, port := hostPort(t, addr)
	user := currentUser(t)
	key := userCertFile(t, ca)

	// Build a commit locally and push it over SSH.
	work := t.TempDir()
	write := func(p, c string) {
		if err = os.WriteFile(filepath.Join(work, p), []byte(c), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	run := func(name string, args ...string) {
		c := exec.Command(name, args...)
		c.Dir = work
		out, err = c.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("git", "init", "-q")
	write("a.txt", "git over nokkud\n")
	run("git", "add", "a.txt")
	run(
		"git",
		"-c",
		"user.email=test@nokku.sh",
		"-c",
		"user.name=test",
		"commit",
		"-q",
		"-m",
		"init",
	)

	sshCmd := fmt.Sprintf(
		"ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		port,
		key,
	)
	url := fmt.Sprintf("ssh://%s@%s/%s", user, host, repo)
	push := exec.Command(git, "push", "-q", url, "HEAD:main")
	push.Dir = work
	push.Env = append(os.Environ(), "GIT_SSH_COMMAND="+sshCmd)
	out, err = push.CombinedOutput()
	if err != nil {
		t.Fatalf("git push: %v\n%s", err, out)
	}

	// The commit must be reachable in the remote repo.
	verify := exec.Command(git, "rev-parse", "HEAD")
	verify.Dir = work
	head, err := verify.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	head = bytes.TrimSpace(head)
	show := exec.Command(git, "show-ref", "refs/heads/main")
	show.Dir = repo
	out, err = show.Output()
	if err != nil {
		t.Fatalf("remote ref missing: %v\n%s", err, out)
	}
	if !bytes.Contains(out, head) {
		t.Fatalf("remote ref %q not pushed; show-ref = %q", head, out)
	}
}

// hostPort splits a 127.0.0.1:port addr.
func hostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	return host, port
}

// currentHome returns the current user's home directory.
func currentHome(t *testing.T) string {
	t.Helper()
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return cur.HomeDir
}

// userCertFile writes a user key + certificate to a temp dir for real clients
// and returns the path to the private key (scp -i).
func userCertFile(t *testing.T, ca testCA) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("user public key: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-user",
		ValidPrincipals: []string{testPrincipal},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err = cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	certPath := keyPath + "-cert.pub"
	certPub := ssh.MarshalAuthorizedKey(cert)
	if err = os.WriteFile(certPath, certPub, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return keyPath
}

func isTestBinary() bool {
	return filepath.Base(os.Args[0]) == "sshd.test"
}
