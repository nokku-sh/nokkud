// Package state manages the daemon's persisted enrollment config and synced cache.
package state

import (
	"encoding/json"
	"log/slog"
	"slices"
	"sync"

	"github.com/mizuchilabs/kata/fsutil"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// Cache is the thread-safe, persisted state synced from the backend. It backs
// SSH access decisions when the backend is unreachable.
type Cache struct {
	mu           sync.RWMutex
	principals   map[string][]string
	stateVersion int64
	daemonConfig *nokkuv1.DaemonConfig
	ca           string
	retiredCAs   []*nokkuv1.RetiredCAKey
}

// cacheJSON is the on-disk representation of a Cache. Cache's fields stay
// unexported so every access goes through the mutex.
type cacheJSON struct {
	Principals   map[string][]string     `json:"principals"`
	StateVersion int64                   `json:"state_version,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig   `json:"daemon_config,omitempty"`
	CA           string                  `json:"ca,omitempty"`
	RetiredCAs   []*nokkuv1.RetiredCAKey `json:"retired_cas,omitempty"`
}

func NewCache() *Cache {
	return &Cache{
		principals: make(map[string][]string),
	}
}

// GetUUIDs returns a copy of the principal's UUIDs.
func (c *Cache) GetUUIDs(principal string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return slices.Clone(c.principals[principal])
}

func (c *Cache) GetStateVersion() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stateVersion
}

// SetDaemonConfig replaces the backend-synced daemon config, which session
// goroutines read concurrently.
func (c *Cache) SetDaemonConfig(dc *nokkuv1.DaemonConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.daemonConfig = dc
}

// DaemonConfig returns the synced daemon config. Callers must treat it as read-only.
func (c *Cache) DaemonConfig() *nokkuv1.DaemonConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.daemonConfig
}

// CAs returns the CA public key user certificates must be signed by, and the
// rolled-over keys that are still trusted. Callers must treat the retired
// keys as read-only.
func (c *Cache) CAs() (active string, retired []*nokkuv1.RetiredCAKey) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ca, c.retiredCAs
}

// Replace atomically swaps the whole cached state so auth reads never observe
// an intermediate empty map and a concurrent login is not denied mid-sync.
func (c *Cache) Replace(
	principals map[string][]string,
	dc *nokkuv1.DaemonConfig,
	ca string,
	retiredCAs []*nokkuv1.RetiredCAKey,
	version int64,
) {
	next := validPrincipals(principals)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principals = next
	c.daemonConfig = dc
	c.ca = ca
	c.retiredCAs = retiredCAs
	c.stateVersion = version
}

// validPrincipals deep-copies m, dropping any name that is not a safe POSIX
// username.
func validPrincipals(m map[string][]string) map[string][]string {
	next := make(map[string][]string, len(m))
	for principal, uuids := range m {
		if err := validatePrincipal(principal); err != nil {
			slog.Debug("skipping invalid principal", "error", err)
			continue
		}
		next[principal] = slices.Clone(uuids)
	}
	return next
}

// Clear drops all cached synced state, persisted on the next Save.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principals = make(map[string][]string)
	c.stateVersion = 0
	c.daemonConfig = nil
	c.ca = ""
	c.retiredCAs = nil
}

// Load reads the cache from disk, ignoring a corrupted file so the next sync
// rebuilds it. A missing file is not an error.
func (c *Cache) Load() error {
	return fsutil.LoadJSON(paths.CacheFile(), c)
}

// Save writes the cache atomically, skipping unchanged content.
func (c *Cache) Save() error {
	return fsutil.SaveJSON(paths.CacheFile(), c, 0o640)
}

func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(cacheJSON{
		Principals:   c.principals,
		StateVersion: c.stateVersion,
		DaemonConfig: c.daemonConfig,
		CA:           c.ca,
		RetiredCAs:   c.retiredCAs,
	})
}

// UnmarshalJSON validates like Replace, so a hand-edited file cannot sneak
// in an unsafe name.
func (c *Cache) UnmarshalJSON(data []byte) error {
	var dto cacheJSON
	if err := json.Unmarshal(data, &dto); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principals = validPrincipals(dto.Principals)
	c.stateVersion = dto.StateVersion
	c.daemonConfig = dto.DaemonConfig
	c.ca = dto.CA
	c.retiredCAs = dto.RetiredCAs
	return nil
}
