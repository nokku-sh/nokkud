package sysutil

import (
	"fmt"
	"net/netip"
	"os"
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

func TestLookupAccount(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	withFakeGetent(
		t,
		fakeGetentScript(0, "nokkud-test-alice:x:1001:1002:Alice Test:/home/alice:/bin/bash"),
	)

	a, err := LookupAccount("nokkud-test-alice")
	must.NoError(err)
	is.Equal(Account{Name: "nokkud-test-alice", UID: 1001, GID: 1002, Home: "/home/alice", Shell: "/bin/bash"}, *a)
}

func TestLookupAccountShell(t *testing.T) {
	for name, tt := range map[string]struct{ entry, want string }{
		"a lock shell is used as it stands": {"nokkud-test-alice:x:1001:1002::/home/alice:/usr/sbin/nologin", "/usr/sbin/nologin"},
		"an empty shell means /bin/sh":      {"nokkud-test-alice:x:1001:1002::/home/alice:", "/bin/sh"},
	} {
		t.Run(name, func(t *testing.T) {
			withFakeGetent(t, fakeGetentScript(0, tt.entry))
			a, err := LookupAccount("nokkud-test-alice")
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Shell)
		})
	}
}

func TestLookupAccountRefused(t *testing.T) {
	for name, script := range map[string]string{
		"getent fails":        fakeGetentScript(1, ""),
		"short entry":         fakeGetentScript(0, "nokkud-test-bob:x:1001"),
		"uid is not a number": fakeGetentScript(0, "nokkud-test-bob:x:abc:1002::/home/bob:/bin/sh"),
		// getent resolves a number as a uid and answers with that account.
		"entry for another name": fakeGetentScript(0, "root:x:0:0:root:/root:/bin/bash"),
	} {
		t.Run(name, func(t *testing.T) {
			withFakeGetent(t, script)
			_, err := LookupAccount("nokkud-test-bob")
			assert.Error(t, err)
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

	env := CmdEnv(&Account{Name: "alice", Home: "/home/alice", Shell: "/bin/sh"})
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
		"TZ":      "Europe/Berlin",
	} {
		is.Equal(want, got[key])
	}
	is.NotEmpty(got["PATH"])

	// TERM is the session's to set, the daemon's own never passes.
	for _, leaked := range []string{"TERM", "DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK", "SSH_CONNECTION", "LD_PRELOAD", "BASH_ENV"} {
		is.NotContains(got, leaked)
	}
}

func TestLoginAllowed(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	path := filepath.Join(t.TempDir(), "nologin")

	nonRoot := &Account{Name: "alice", UID: 1000}
	root := &Account{Name: "root"}

	is.NoError(LoginAllowed(nonRoot, path), "missing file must allow logins")
	is.NoError(LoginAllowed(root, path), "missing file must allow root")

	must.NoError(os.WriteFile(path, []byte("maintenance until 17:00\n"), 0o644))
	err := LoginAllowed(nonRoot, path)
	must.Error(err, "nologin must deny a non-root login")
	is.Contains(err.Error(), "maintenance until 17:00")

	is.NoError(LoginAllowed(root, path), "nologin must never block root")
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
