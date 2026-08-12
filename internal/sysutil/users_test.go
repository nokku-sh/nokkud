package sysutil

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeGetent puts a fake getent binary first on PATH that prints output
// for every invocation, so the NSS/LDAP fallback paths can be exercised
// without a real directory service.
func withFakeGetent(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "getent"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake getent: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fakeGetentScript(exitCode int, output string) string {
	if exitCode != 0 {
		return fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	}
	return fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\n", output)
}

func TestLookupUserFallsBackToGetent(t *testing.T) {
	withFakeGetent(
		t,
		fakeGetentScript(0, "nokkud-test-alice:x:1001:1002:Alice Test:/home/alice:/bin/bash"),
	)

	u, err := LookupUser("nokkud-test-alice")
	if err != nil {
		t.Fatalf("LookupUser: %v", err)
	}
	if u.Username != "nokkud-test-alice" || u.Uid != "1001" || u.Gid != "1002" ||
		u.Name != "Alice Test" || u.HomeDir != "/home/alice" {
		t.Fatalf("LookupUser = %+v, want getent fields parsed", u)
	}
}

func TestLookupUserMalformedGetentOutput(t *testing.T) {
	withFakeGetent(t, fakeGetentScript(0, "nokkud-test-bob:x:1001"))

	if _, err := LookupUser("nokkud-test-bob"); err == nil {
		t.Fatal("LookupUser accepted a truncated passwd line")
	}
}

func TestLookupUserGetentFailure(t *testing.T) {
	withFakeGetent(t, fakeGetentScript(1, ""))

	if _, err := LookupUser("nokkud-test-ghost"); err == nil {
		t.Fatal("LookupUser accepted a failing getent")
	}
}

func TestUserShellFromGetent(t *testing.T) {
	withFakeGetent(t, fakeGetentScript(0, "nokkud-test-alice:x:1001:1002::/home/alice:/bin/sh"))

	u := &user.User{Username: "nokkud-test-alice"}
	if got := UserShell(u); got != "/bin/sh" {
		t.Fatalf("UserShell = %q, want /bin/sh", got)
	}
}

func TestUserShellFallsBackWhenShellNotExecutable(t *testing.T) {
	withFakeGetent(
		t,
		fakeGetentScript(0, "nokkud-test-alice:x:1001:1002::/home/alice:/nonexistent-shell"),
	)
	t.Setenv("SHELL", "/bin/sh")

	u := &user.User{Username: "nokkud-test-alice"}
	if got := UserShell(u); got != "/bin/sh" {
		t.Fatalf("UserShell = %q, want SHELL fallback", got)
	}
}

func TestUserShellFallsBackOnMalformedEntry(t *testing.T) {
	withFakeGetent(t, fakeGetentScript(0, "nokkud-test-alice:x:1001"))
	t.Setenv("SHELL", "/bin/sh")

	u := &user.User{Username: "nokkud-test-alice"}
	if got := UserShell(u); got != "/bin/sh" {
		t.Fatalf("UserShell = %q, want SHELL fallback", got)
	}
}

func TestCmdEnv(t *testing.T) {
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("TERM", "screen-256color")
	t.Setenv("TZ", "Europe/Berlin")
	// These must never leak into sessions.
	t.Setenv("DISPLAY", ":0")
	t.Setenv("XAUTHORITY", "/tmp/xauth")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/leak.sock")
	t.Setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 10")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("BASH_ENV", "/tmp/evil")

	env := CmdEnv(&user.User{Username: "alice", HomeDir: "/home/alice"}, "/bin/sh")
	got := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("env entry without '=': %q", kv)
		}
		got[k] = v
	}

	for key, want := range map[string]string{
		"HOME":    "/home/alice",
		"USER":    "alice",
		"LOGNAME": "alice",
		"SHELL":   "/bin/sh",
		"LANG":    "de_DE.UTF-8",
		"TERM":    "screen-256color",
		"TZ":      "Europe/Berlin",
	} {
		if got[key] != want {
			t.Errorf("env[%s] = %q, want %q", key, got[key], want)
		}
	}
	if got["PATH"] == "" {
		t.Error("env[PATH] is empty")
	}

	for _, leaked := range []string{"DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK", "SSH_CONNECTION", "LD_PRELOAD", "BASH_ENV"} {
		if _, ok := got[leaked]; ok {
			t.Errorf("sensitive variable %s leaked into session env", leaked)
		}
	}
}

func TestIsExecutable(t *testing.T) {
	dir := t.TempDir()

	execFile := filepath.Join(dir, "exec")
	if err := os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write exec file: %v", err)
	}
	plainFile := filepath.Join(dir, "plain")
	if err := os.WriteFile(plainFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}

	if !IsExecutable(execFile) {
		t.Error("IsExecutable(0755 file) = false, want true")
	}
	if IsExecutable(plainFile) {
		t.Error("IsExecutable(0644 file) = true, want false")
	}
	if IsExecutable(dir) {
		t.Error("IsExecutable(dir) = true, want false")
	}
	if IsExecutable(filepath.Join(dir, "missing")) {
		t.Error("IsExecutable(missing) = true, want false")
	}
}

func TestIsNoiseInterface(t *testing.T) {
	for _, name := range []string{"docker0", "veth123", "br-1", "virbr0", "lo", "dummy0", "cali-ab12", "flannel.1", "bond1"} {
		if !isNoiseInterface(name) {
			t.Errorf("isNoiseInterface(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"eth0", "enp3s0", "wg0", "utun3"} {
		if isNoiseInterface(name) {
			t.Errorf("isNoiseInterface(%q) = true, want false", name)
		}
	}
	if !isNoiseInterface("Hyper-V Virtual Ethernet Adapter") {
		t.Error("hyper-v interface not classified as noise")
	}
	if !isNoiseInterface("DOCKER0") {
		t.Error("classification must be case-insensitive")
	}
}

func TestHasAnyPrefixIsCaseInsensitive(t *testing.T) {
	if !hasAnyPrefix("ETH0", []string{"eth"}) {
		t.Error("hasAnyPrefix must match case-insensitively")
	}
	if hasAnyPrefix("veth0", []string{"eth"}) {
		t.Error("hasAnyPrefix matched a non-prefix")
	}
}

func TestIsPublicOrPrivateNIC(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.5", "8.8.8.8", "100.64.0.1"} {
		if !isPublicOrPrivateNIC(netip.MustParseAddr(ip)) {
			t.Errorf("isPublicOrPrivateNIC(%s) = false, want true", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1"} {
		if isPublicOrPrivateNIC(netip.MustParseAddr(ip)) {
			t.Errorf("isPublicOrPrivateNIC(%s) = true, want false", ip)
		}
	}
}
