package state

import (
	"github.com/mizuchilabs/kata/fsutil"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// DefaultAPIURL applies until --api or config.json says otherwise.
const DefaultAPIURL = "https://app.nokku.sh"

// Config is the persisted enrollment state. The backend-synced daemon config
// lives in [Cache].
type Config struct {
	TargetID     string `json:"target_id,omitempty"`
	DaemonID     string `json:"daemon_id,omitempty"`
	APIURL       string `json:"api_url,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

// Load reads the config from disk. A missing file is not an error.
func (c *Config) Load() error {
	return fsutil.LoadJSON(paths.ConfigFile(), c)
}

// Save writes the config atomically with 0600 perms.
func (c *Config) Save() error {
	return fsutil.SaveJSON(paths.ConfigFile(), c, 0o600)
}
