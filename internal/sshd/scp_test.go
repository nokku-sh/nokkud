package sshd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestServerSCPLegacy exercises the legacy SCP protocol (scp -O) end to end,
// using the real scp binary as the client. Skip when scp is unavailable.
func TestServerSCPLegacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scp not available")
	}
	if !isTestBinary() {
		t.Skip("legacy scp test requires the test binary on PATH")
	}
	if _, err := exec.LookPath("scp"); err != nil {
		t.Skip("scp not installed")
	}

	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	user := currentUser(t)
	home := currentHome(t)
	_, port := hostPort(t, addr)
	scratches := filepath.Join(home, "nokkud-scp-scratch")
	if err := os.RemoveAll(scratches); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratches)
	if err := os.MkdirAll(scratches, 0o755); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(scratches, "src.txt")
	if err := os.WriteFile(src, []byte("legacy scp payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	identity := userCertFile(t, ca)
	opts := []string{
		"-O",
		"-q",
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(scratches, "known_hosts"),
		"-P", port,
	}
	// copy up
	up := filepath.Join(scratches, "up.txt")
	cmd := exec.Command("scp", append(opts, src, fmt.Sprintf("%s@127.0.0.1:%s", user, up))...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scp up: %v: %s", err, out)
	}
	if b, err := os.ReadFile(up); err != nil || string(b) != "legacy scp payload\n" {
		t.Fatalf("scp up content: %q err=%v", b, err)
	}
	// copy down
	dst := filepath.Join(scratches, "dst.txt")
	cmd = exec.Command("scp", append(opts, fmt.Sprintf("%s@127.0.0.1:%s", user, src), dst)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scp down: %v: %s", err, out)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "legacy scp payload\n" {
		t.Fatalf("scp down content: %q err=%v", b, err)
	}

	// Recursive directory copy up. Destination must exist for the source
	// directory name to be preserved (scp quirk).
	srcdir := filepath.Join(scratches, "srcdir")
	inner := filepath.Join(srcdir, "sub")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "f.txt"), []byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	uptree := filepath.Join(scratches, "uptree")
	if err := os.Mkdir(uptree, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(
		"scp",
		append(opts, "-r", srcdir, fmt.Sprintf("%s@127.0.0.1:%s", user, uptree))...,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scp -r up: %v: %s", err, out)
	}
	if b, err := os.ReadFile(
		filepath.Join(uptree, "srcdir", "sub", "f.txt"),
	); err != nil ||
		string(b) != "nested\n" {
		t.Fatalf("scp -r up content: %q err=%v", b, err)
	}
}
