package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/sshd"
)

func TestSSHPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		want string
	}{
		{addr: "", want: ""},
		{addr: ":4022", want: "4022"},
		{addr: "0.0.0.0:4022", want: "4022"},
		{addr: "[::]:4022", want: "4022"},
		{addr: "127.0.0.1:4022", want: "4022"},
		{addr: "4022", want: "4022"},
		{addr: "0", want: ""},
		{addr: "65535", want: "65535"},
		{addr: "65536", want: ""},
		{addr: "-1", want: ""},
		{addr: "not-a-port", want: ""},
		{addr: "127.0.0.1:not-a-port", want: ""},
		{addr: "127.0.0.1:0", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, sshPort(tt.addr))
		})
	}
}

func TestValidPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		port string
		want string
	}{
		{port: "4022", want: "4022"},
		{port: "00080", want: "00080"},
		{port: "0", want: ""},
		{port: "65536", want: ""},
		{port: "", want: ""},
		{port: " 22", want: ""},
		{port: "22 ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.port, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, validPort(tt.port))
		})
	}
}

// TestCaMatches verifies the cached CA comparison used to detect rollovers:
// content equality, whitespace tolerance, and the missing-file case.
func TestCaMatches(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)
	caPath := filepath.Join(dir, "nokku_ca.pub")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw2BPSytSBKCcOmfUWab8JA2uRKsEUO/FtuZACsJccE"

	c := &Client{}

	is.False(c.caMatches(key), "caMatches must report false when no CA file exists")

	must.NoError(os.WriteFile(caPath, []byte(key+"\n"), 0o644))
	is.True(c.caMatches(key), "caMatches must match the cached CA")
	is.True(c.caMatches(key+"\n   "), "caMatches must tolerate surrounding whitespace")
	is.False(c.caMatches(key[:len(key)-1]+"X"), "caMatches must reject a different CA")
	is.True(c.caMatches(strings.TrimSpace(key)), "caMatches must ignore whitespace differences")
}

// TestOverlayConfigDefaults verifies a synced config that omits a field keeps
// the daemon's compiled-in policy instead of zeroing it, so a partial backend
// config cannot silently turn recording (or forwarding) off.
func TestOverlayConfigDefaults(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	defaults := sshd.Tunables{
		Record:               true,
		AllowForwarding:      true,
		AllowAgentForwarding: true,
		Banner:               true,
		MaxSessions:          10,
		MaxChannels:          50,
		MaxStartups:          10,
	}

	// A config with no fields set at all keeps every default.
	is.Equal(defaults, overlayConfig(defaults, &nokkuv1.DaemonConfig{}))

	// An explicit false still overrides.
	off := false
	got := overlayConfig(defaults, &nokkuv1.DaemonConfig{RecordSessions: &off})
	is.False(got.Record, "explicit record_sessions=false must disable recording")
	is.True(got.Banner, "unset fields must keep their default")

	// An explicit true overrides a default of false.
	on := true
	defaults.Banner = false
	got = overlayConfig(defaults, &nokkuv1.DaemonConfig{Banner: &on})
	is.True(got.Banner, "explicit banner=true must override the default")

	// A numeric override applies while unset fields keep their default.
	maxStartups := int32(25)
	got = overlayConfig(defaults, &nokkuv1.DaemonConfig{MaxStartups: &maxStartups})
	is.Equal(25, got.MaxStartups, "explicit max_startups must override the default")
	is.Equal(10, got.MaxSessions, "unset max_sessions must keep its default")

	// The hardening fields follow the same presence semantics.
	maxChannels := int32(20)
	dropRetired := true
	got = overlayConfig(defaults, &nokkuv1.DaemonConfig{
		MaxChannels:   &maxChannels,
		DropRetiredCa: &dropRetired,
	})
	is.Equal(20, got.MaxChannels, "explicit max_channels must override the default")
	is.True(got.DropRetiredCA, "explicit drop_retired_ca must override the default")

	// A nil config leaves the defaults untouched.
	is.Equal(defaults, overlayConfig(defaults, nil))
}
