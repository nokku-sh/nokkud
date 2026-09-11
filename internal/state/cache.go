// Package state manages the daemon's persisted enrollment config and synced cache.
package state

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// revocationWindow is longer than the backend's 7 day certificate lifetime cap,
// so a cert minted just before a revocation is still refused for its whole life.
const revocationWindow = 8 * 24 * time.Hour

// Cache is the thread-safe, persisted state synced from the backend. It backs
// SSH access decisions when the backend is unreachable.
type Cache struct {
	mu           sync.RWMutex
	principals   map[string][]string
	revocations  map[string]int64
	stateVersion int64
	daemonConfig *nokkuv1.DaemonConfig
}

// cacheJSON is the on-disk representation of a Cache. Cache's fields stay
// unexported so every access goes through the mutex.
type cacheJSON struct {
	Principals   map[string][]string   `json:"principals"`
	Revocations  map[string]int64      `json:"revocations,omitempty"`
	StateVersion int64                 `json:"state_version,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig `json:"daemon_config,omitempty"`
}

func NewCache() *Cache {
	return &Cache{
		principals:  make(map[string][]string),
		revocations: make(map[string]int64),
	}
}

// GetUUIDs returns a copy of the principal's UUIDs.
func (c *Cache) GetUUIDs(principal string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uuids := c.principals[principal]
	result := make([]string, len(uuids))
	copy(result, uuids)
	return result
}

// RevokedBefore returns the revocation cutoff for a principal. A certificate
// with an earlier ValidAfter is refused.
func (c *Cache) RevokedBefore(principal string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	before, ok := c.revocations[principal]
	return before, ok
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

// Replace atomically swaps the whole cached state so auth reads never observe
// an intermediate empty map and a concurrent login is not denied mid-sync.
func (c *Cache) Replace(
	principals map[string][]string,
	revocations map[string]int64,
	dc *nokkuv1.DaemonConfig,
	version int64,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := make(map[string][]string, len(principals))
	for principal, uuids := range principals {
		if err := util.ValidatePrincipal(principal); err != nil {
			slog.Debug("skipping invalid principal", "user", principal)
			continue
		}
		ids := make([]string, len(uuids))
		copy(ids, uuids)
		next[principal] = ids
	}

	cutoff := time.Now().Add(-revocationWindow).Unix()
	nextRevocations := make(map[string]int64, len(revocations))
	for principal, before := range revocations {
		if before < cutoff {
			continue
		}
		nextRevocations[principal] = before
	}

	c.principals = next
	c.revocations = nextRevocations
	c.daemonConfig = dc
	c.stateVersion = version
}

// Clear drops all cached synced state, persisted on the next Save.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principals = make(map[string][]string)
	c.revocations = make(map[string]int64)
	c.stateVersion = 0
	c.daemonConfig = nil
}

// Load reads the cache from disk, discarding a corrupted file so the next sync
// rebuilds it. A missing file is not an error.
func (c *Cache) Load() error {
	return loadJSON(paths.CacheFile(), c)
}

// Save writes the cache atomically, skipping unchanged content.
func (c *Cache) Save() error {
	return saveJSON(paths.CacheFile(), c, 0o640)
}

func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(cacheJSON{
		Principals:   c.principals,
		Revocations:  c.revocations,
		StateVersion: c.stateVersion,
		DaemonConfig: c.daemonConfig,
	})
}

// UnmarshalJSON always leaves usable, non-nil maps behind.
func (c *Cache) UnmarshalJSON(data []byte) error {
	var dto cacheJSON
	if err := json.Unmarshal(data, &dto); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if dto.Principals == nil {
		c.principals = make(map[string][]string)
	} else {
		c.principals = dto.Principals
	}
	if dto.Revocations == nil {
		c.revocations = make(map[string]int64)
	} else {
		c.revocations = dto.Revocations
	}
	c.stateVersion = dto.StateVersion
	c.daemonConfig = dto.DaemonConfig
	return nil
}
