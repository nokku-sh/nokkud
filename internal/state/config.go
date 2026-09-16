package state

import (
	"github.com/nokku-sh/mon/fsutil"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// Built-in defaults for the runtime options the daemon persists. They live
// here, not on the CLI flags, so a bare default never clobbers config.json.
const (
	DefaultAPIURL  = "https://app.nokku.sh"
	DefaultSSHAddr = ":4022"
)

// Config is the persisted enrollment state. The backend-synced daemon config
// lives in [Cache].
type Config struct {
	WorkspaceID  string `json:"workspace_id,omitempty"`
	TargetID     string `json:"target_id,omitempty"`
	DaemonID     string `json:"daemon_id,omitempty"`
	APIURL       string `json:"api_url,omitempty"`
	SSHAddr      string `json:"ssh_addr,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

func NewConfig() *Config {
	return &Config{}
}

// Load reads the config from disk. A missing file is not an error.
func (c *Config) Load() error {
	return fsutil.LoadJSON(paths.ConfigFile(), c)
}

// Save writes the config atomically with 0600 perms.
func (c *Config) Save() error {
	return fsutil.SaveJSON(paths.ConfigFile(), c, 0o600)
}

func (c *Config) Clear() {
	c.WorkspaceID = ""
	c.TargetID = ""
	c.DaemonID = ""
	c.APIURL = ""
	c.SSHAddr = ""
	c.SessionToken = ""
}
