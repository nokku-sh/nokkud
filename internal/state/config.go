package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// Config is the persisted enrollment state: target/daemon IDs, API
// endpoint and runtime options. paths is never serialized.
type Config struct {
	WorkspaceID  string                `json:"workspace_id,omitempty"`
	TargetID     string                `json:"target_id,omitempty"`
	DaemonID     string                `json:"daemon_id,omitempty"`
	APIURL       string                `json:"api_url,omitempty"`
	SSHAddr      string                `json:"ssh_addr,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig `json:"daemon_config,omitempty"`

	mu    sync.RWMutex
	paths paths.Paths
}

// NewConfig returns an empty config bound to the given paths.
func NewConfig(p paths.Paths) *Config {
	return &Config{paths: p}
}

// Load reads the config from disk. A missing file is not an error. A
// corrupted one is cleared so the daemon starts unenrolled, never
// half-enrolled.
func (c *Config) Load() error {
	data, err := os.ReadFile(c.paths.ConfigFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading config: %w", err)
	}
	if err = json.Unmarshal(data, c); err != nil {
		c.Clear()
		if rmErr := os.Remove(c.paths.ConfigFile()); rmErr != nil {
			slog.Warn("remove corrupted config", "error", rmErr)
		}
		return nil
	}
	return nil
}

// Save writes the config atomically with 0600 perms, skipping unchanged
// content.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing config: %w", err)
	}

	if err = util.WriteIfChanged(c.paths.ConfigFile(), data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// SetDaemonConfig replaces the synced backend config. The field is also
// read by session goroutines, so every write goes through this lock.
func (c *Config) SetDaemonConfig(dc *nokkuv1.DaemonConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DaemonConfig = dc
}

// RecordingKey returns the workspace recording public key from the synced
// config, or "" when recording encryption is disabled.
func (c *Config) RecordingKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.DaemonConfig.GetRecordingPublicKey()
}

// RecordSessions reports whether the synced config enables session recording.
func (c *Config) RecordSessions() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.DaemonConfig.GetRecordSessions()
}

// Clear resets the config to its zero state, keeping the paths binding.
func (c *Config) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.WorkspaceID = ""
	c.TargetID = ""
	c.DaemonID = ""
	c.APIURL = ""
	c.SSHAddr = ""
	c.DaemonConfig = nil
}
