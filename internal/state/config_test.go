package state

import (
	"os"
	"strings"
	"testing"

	"github.com/nokku-sh/nokkud/internal/paths"
)

func newTestPaths(t *testing.T) paths.Paths {
	t.Helper()
	return paths.Paths{ConfigDir: t.TempDir()}
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	c.TargetID = "tgt-1"
	c.DaemonID = "daemon-1"
	c.APIURL = "https://api.example.com"
	c.CAID = "ca-1"
	c.SSHAddr = ":4022"

	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := NewConfig(p)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.WorkspaceID != "ws-1" || loaded.TargetID != "tgt-1" ||
		loaded.DaemonID != "daemon-1" || loaded.APIURL != "https://api.example.com" ||
		loaded.CAID != "ca-1" || loaded.SSHAddr != ":4022" {
		t.Fatalf("loaded config = %+v, want all fields set", loaded)
	}
}

func TestConfigLoadMissingFileIsNotAnError(t *testing.T) {
	t.Parallel()
	c := NewConfig(newTestPaths(t))
	if err := c.Load(); err != nil {
		t.Fatalf("Load on missing file: %v, want nil", err)
	}
}

func TestConfigLoadCorruptedClearsAndRemoves(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(p.ConfigFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt config: %v", err)
	}

	loaded := NewConfig(p)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load on corrupted config: %v, want nil (daemon must start unenrolled)", err)
	}
	if loaded.WorkspaceID != "" {
		t.Fatalf("corrupted config left state behind: %+v", loaded)
	}
	if _, err := os.Stat(p.ConfigFile()); !os.IsNotExist(err) {
		t.Fatalf("corrupted config file was not removed: %v", err)
	}
}

func TestConfigClearKeepsPathsBinding(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	c.Clear()

	if c.WorkspaceID != "" {
		t.Fatalf("Clear left fields set: %+v", c)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save after Clear must still target the bound paths: %v", err)
	}
	if _, err := os.Stat(p.ConfigFile()); err != nil {
		t.Fatalf("config file not written where expected: %v", err)
	}
}

func TestConfigSaveSkipsUnchanged(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(p.ConfigFile())
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if err = c.Save(); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	fi2, err := os.Stat(p.ConfigFile())
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if !fi.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("unchanged Save rewrote the file")
	}
}

func TestConfigSaveWritesWithPrivatePerms(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(p.ConfigFile())
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config perm = %o, want 600", perm)
	}
}

func TestConfigFileNeverContainsPaths(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewConfig(p)
	c.WorkspaceID = "ws-1"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(p.ConfigFile())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	// The ConfigDir must not leak into the serialized enrollment state,
	// which is shared with the control plane.
	if strings.Contains(string(data), p.ConfigDir) {
		t.Fatal("config file contains the config dir path")
	}
}
