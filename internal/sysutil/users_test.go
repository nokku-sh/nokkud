package sysutil

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFakeGetent puts a fake getent binary first on PATH that prints output
// for every invocation, so the NSS/LDAP fallback paths can be exercised
// without a real directory service.
func withFakeGetent(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	must := require.New(t)
	must.NoError(os.WriteFile(filepath.Join(dir, "getent"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fakeGetentScript(exitCode int, output string) string {
	if exitCode != 0 {
		return fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	}
	return fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\n", output)
}

func TestLookupUserFallsBackToGetent(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	withFakeGetent(
		t,
		fakeGetentScript(0, "nokkud-test-alice:x:1001:1002:Alice Test:/home/alice:/bin/bash"),
	)

	u, err := LookupUser("nokkud-test-alice")
	must.NoError(err)
	is.Equal("nokkud-test-alice", u.Username)
	is.Equal("1001", u.Uid)
	is.Equal("1002", u.Gid)
	is.Equal("Alice Test", u.Name)
	is.Equal("/home/alice", u.HomeDir)
}

func TestLookupUserMalformedGetentOutput(t *testing.T) {
	is := assert.New(t)
	withFakeGetent(t, fakeGetentScript(0, "nokkud-test-bob:x:1001"))

	_, err := LookupUser("nokkud-test-bob")
	is.Error(err)
}

func TestLookupUserGetentFailure(t *testing.T) {
	is := assert.New(t)
	withFakeGetent(t, fakeGetentScript(1, ""))

	_, err := LookupUser("nokkud-test-ghost")
	is.Error(err)
}

func TestUserShell(t *testing.T) {
	tests := []struct {
		name     string
		getent   string
		shellEnv string
		want     string
	}{
		{
			name:     "shell from getent",
			getent:   fakeGetentScript(0, "nokkud-test-alice:x:1001:1002::/home/alice:/bin/sh"),
			shellEnv: "",
			want:     "/bin/sh",
		},
		{
			name:     "getent shell not executable falls back to SHELL",
			getent:   fakeGetentScript(0, "nokkud-test-alice:x:1001:1002::/home/alice:/nonexistent-shell"),
			shellEnv: "/bin/sh",
			want:     "/bin/sh",
		},
		{
			name:     "malformed getent entry falls back to SHELL",
			getent:   fakeGetentScript(0, "nokkud-test-alice:x:1001"),
			shellEnv: "/bin/sh",
			want:     "/bin/sh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			withFakeGetent(t, tt.getent)
			t.Setenv("SHELL", tt.shellEnv)

			u := &user.User{Username: "nokkud-test-alice"}
			is.Equal(tt.want, UserShell(u))
		})
	}
}

func TestCmdEnv(t *testing.T) {
	is := assert.New(t)
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
	must := require.New(t)
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		must.True(ok, "env entry without '=': %q", kv)
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
		is.Equal(want, got[key])
	}
	is.NotEmpty(got["PATH"])

	for _, leaked := range []string{"DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK", "SSH_CONNECTION", "LD_PRELOAD", "BASH_ENV"} {
		is.NotContains(got, leaked)
	}
}

func TestIsExecutable(t *testing.T) {
	must := require.New(t)
	dir := t.TempDir()

	execFile := filepath.Join(dir, "exec")
	must.NoError(os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0o755))
	plainFile := filepath.Join(dir, "plain")
	must.NoError(os.WriteFile(plainFile, []byte("x"), 0o644))

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "executable file", path: execFile, want: true},
		{name: "plain file", path: plainFile, want: false},
		{name: "directory", path: dir, want: false},
		{name: "missing file", path: filepath.Join(dir, "missing"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, IsExecutable(tt.path))
		})
	}
}

func TestIsNoiseInterface(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"docker0", true},
		{"veth123", true},
		{"br-1", true},
		{"virbr0", true},
		{"lo", true},
		{"dummy0", true},
		{"cali-ab12", true},
		{"flannel.1", true},
		{"bond1", true},
		{"eth0", false},
		{"enp3s0", false},
		{"wg0", false},
		{"utun3", false},
		{"Hyper-V Virtual Ethernet Adapter", true},
		{"DOCKER0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, isNoiseInterface(tt.name))
		})
	}
}

func TestHasAnyPrefixIsCaseInsensitive(t *testing.T) {
	is := assert.New(t)
	is.True(hasAnyPrefix("ETH0", []string{"eth"}))
	is.False(hasAnyPrefix("veth0", []string{"eth"}))
}

func TestIsPublicOrPrivateNIC(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.5", true},
		{"8.8.8.8", true},
		{"100.64.0.1", true},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"::1", false},
		{"fe80::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, isPublicOrPrivateNIC(netip.MustParseAddr(tt.ip)))
		})
	}
}
