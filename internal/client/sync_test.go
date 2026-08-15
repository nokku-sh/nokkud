package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/state"
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
			if got := sshPort(tt.addr); got != tt.want {
				t.Errorf("sshPort(%q) = %q, want %q", tt.addr, got, tt.want)
			}
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
			if got := validPort(tt.port); got != tt.want {
				t.Errorf("validPort(%q) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}

// fakeDaemonService is a DaemonServiceClient stub that returns a canned
// SyncDaemon response. Only SyncDaemon is overridden; the embedded nil
// interface provides the rest without ever being called.
type fakeDaemonService struct {
	nokkuv1connect.DaemonServiceClient

	resp *nokkuv1.SyncDaemonResponse
}

func (f *fakeDaemonService) SyncDaemon(
	_ context.Context,
	_ *nokkuv1.SyncDaemonRequest,
) (*nokkuv1.SyncDaemonResponse, error) {
	return f.resp, nil
}

// TestSyncDaemonPersistsRecordingKey guards the invariant that a synced
// daemon config reaches the on-disk cache, so a restart keeps the recording
// key even before the first re-sync.
func TestSyncDaemonPersistsRecordingKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := paths.Paths{ConfigDir: dir}

	cfg := state.NewConfig(p)
	cfg.WorkspaceID = "ws-1"
	cfg.TargetID = "tgt-1"
	cfg.DaemonID = "daemon-1"

	key := "dGVzdGtleTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA=="
	version := int64(42)
	c := &Client{
		config: cfg,
		cache:  state.NewCache(p),
		paths:  p,
		dc: &fakeDaemonService{resp: &nokkuv1.SyncDaemonResponse{
			Status:       nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED.Enum(),
			StateVersion: &version,
			Config: &nokkuv1.DaemonConfig{
				RecordingPublicKey: &key,
			},
		}},
	}

	if err := c.syncDaemon(context.Background()); err != nil {
		t.Fatalf("syncDaemon: %v", err)
	}

	loaded := state.NewCache(p)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := loaded.RecordingKey(); got != key {
		t.Fatalf("recording key not persisted: got %q, want %q", got, key)
	}
}

// TestCaMatches verifies the cached CA comparison used to detect rollovers:
// content equality, whitespace tolerance, and the missing-file case.
func TestCaMatches(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "nokku_ca.pub")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw2BPSytSBKCcOmfUWab8JA2uRKsEUO/FtuZACsJccE"

	c := &Client{paths: paths.Paths{ConfigDir: dir}}

	if c.caMatches(key) {
		t.Fatal("caMatches must report false when no CA file exists")
	}

	if err := os.WriteFile(caPath, []byte(key+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !c.caMatches(key) {
		t.Fatal("caMatches must match the cached CA")
	}
	if !c.caMatches(key + "\n   ") {
		t.Fatal("caMatches must tolerate surrounding whitespace")
	}
	if c.caMatches(key[:len(key)-1] + "X") {
		t.Fatal("caMatches must reject a different CA")
	}
	if c.caMatches(strings.TrimSpace(key)) && !c.caMatches(key) {
		t.Fatal("unexpected result")
	}
}
