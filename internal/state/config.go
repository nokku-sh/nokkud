package state

import "github.com/nokku-sh/nokkud/internal/paths"

// Built-in defaults for the runtime options the daemon persists. They live
// here rather than on the CLI flags so the persisted config is the single
// source of truth and a bare default never clobbers a value the user already
// configured in config.json.
const (
	DefaultAPIURL  = "https://app.nokku.sh"
	DefaultSSHAddr = ":4022"
)

// Config is the persisted enrollment state: target/daemon IDs, API
// endpoint and runtime options. The backend-synced daemon config (session
// recording, recording key, caps) lives in the [Cache]. paths is never
// serialized.
type Config struct {
	WorkspaceID  string `json:"workspace_id,omitempty"`
	TargetID     string `json:"target_id,omitempty"`
	DaemonID     string `json:"daemon_id,omitempty"`
	APIURL       string `json:"api_url,omitempty"`
	SSHAddr      string `json:"ssh_addr,omitempty"`
	SessionToken string `json:"session_token,omitempty"`

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
	return loadJSON(c.paths.ConfigFile(), c, c.Clear)
}

// Save writes the config atomically with 0600 perms, skipping unchanged
// content.
func (c *Config) Save() error {
	return saveJSON(c.paths.ConfigFile(), c, 0o600)
}

// Clear resets the config to its zero state, keeping the paths binding.
func (c *Config) Clear() {
	c.WorkspaceID = ""
	c.TargetID = ""
	c.DaemonID = ""
	c.APIURL = ""
	c.SSHAddr = ""
	c.SessionToken = ""
}
