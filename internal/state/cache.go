// Package state manages the daemon's on-disk enrollment config and the
// cached principal→UUID map that keeps SSH access working offline.
package state

import (
	"encoding/json"
	"log/slog"
	"slices"
	"sync"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// Cache is the thread-safe, persisted state synced from the backend:
// the username→UUID map used for SSH access decisions when the backend is
// unreachable and the backend-controlled daemon config. StateVersion is
// the workspace state version this cache was synced to. The daemon
// re-syncs whenever the backend reports a newer one.
type Cache struct {
	mu           sync.RWMutex
	principals   map[string][]string
	stateVersion int64
	daemonConfig *nokkuv1.DaemonConfig
	paths        paths.Paths
}

// cacheJSON is the on-disk representation of a Cache. Fields are
// unexported on Cache itself so every access goes through the mutex; the
// JSON shape lives here instead.
type cacheJSON struct {
	Principals   map[string][]string   `json:"principals"`
	StateVersion int64                 `json:"state_version,omitempty"`
	DaemonConfig *nokkuv1.DaemonConfig `json:"daemon_config,omitempty"`
}

// NewCache returns an empty, ready-to-use cache backed by the given paths.
func NewCache(p paths.Paths) *Cache {
	return &Cache{
		principals: make(map[string][]string),
		paths:      p,
	}
}

// SetUUIDs replaces the entire list of UUIDs for a given principal.
func (c *Cache) SetUUIDs(principal string, uuids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.preparePrincipal(principal) {
		return
	}

	cacheCopy := make([]string, len(uuids))
	copy(cacheCopy, uuids)

	c.principals[principal] = cacheCopy
}

// preparePrincipal ensures the principal map is non-nil and that principal is
// a safe username, reporting whether a write for it should proceed. The
// caller must hold the write lock.
func (c *Cache) preparePrincipal(principal string) bool {
	if c.principals == nil {
		c.principals = make(map[string][]string)
	}
	if err := util.ValidatePrincipal(principal); err != nil {
		slog.Debug("skipping invalid principal", "principal", principal)
		return false
	}
	return true
}

// GetUUIDs safely retrieves a copy of the UUIDs for a principal.
func (c *Cache) GetUUIDs(principal string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uuids := c.principals[principal]
	result := make([]string, len(uuids))
	copy(result, uuids)
	return result
}

// HasUUID reports whether the principal is authorized for the given subject
// UUID.
func (c *Cache) HasUUID(principal, uuid string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uuids, exists := c.principals[principal]
	if !exists {
		return false
	}
	return slices.Contains(uuids, uuid)
}

// GetStateVersion returns the state version this cache was synced to.
func (c *Cache) GetStateVersion() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stateVersion
}

// SetDaemonConfig replaces the backend-synced daemon config. The recording
// key and session record toggle are read by session goroutines, so every
// write goes through the lock.
func (c *Cache) SetDaemonConfig(dc *nokkuv1.DaemonConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.daemonConfig = dc
}

// DaemonConfig returns the synced daemon config. Callers must treat the
// returned message as read-only.
func (c *Cache) DaemonConfig() *nokkuv1.DaemonConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.daemonConfig
}

// RecordSessions reports whether the synced daemon config enables session
// recording.
func (c *Cache) RecordSessions() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.daemonConfig.GetRecordSessions()
}

// Replace atomically swaps the entire cached synced state. Auth reads
// (GetUUIDs) never observe an intermediate empty map the way a Clear
// followed by per-principal writes would, so a concurrent SSH login cannot
// be denied mid-sync. Invalid principals are skipped.
func (c *Cache) Replace(principals map[string][]string, dc *nokkuv1.DaemonConfig, version int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := make(map[string][]string, len(principals))
	for principal, uuids := range principals {
		if err := util.ValidatePrincipal(principal); err != nil {
			slog.Debug("skipping invalid principal", "principal", principal)
			continue
		}
		ids := make([]string, len(uuids))
		copy(ids, uuids)
		next[principal] = ids
	}
	c.principals = next
	c.daemonConfig = dc
	c.stateVersion = version
}

func (c *Cache) clearLocked() {
	c.principals = make(map[string][]string)
	c.stateVersion = 0
	c.daemonConfig = nil
}

// Clear drops all cached synced state (persisted on the next Save). It must
// run before repopulating a sync so stale data from a previous sync never
// survives.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

// Load reads the cache from disk. A missing file is not an error. A
// corrupted one is discarded so the next sync rebuilds it.
func (c *Cache) Load() error {
	return loadJSON(c.paths.CacheFile(), c, c.Clear)
}

// Save writes the cache atomically, skipping unchanged content.
func (c *Cache) Save() error {
	return saveJSON(c.paths.CacheFile(), c, 0o640)
}

// MarshalJSON serializes the cache under its read lock.
func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(cacheJSON{
		Principals:   c.principals,
		StateVersion: c.stateVersion,
		DaemonConfig: c.daemonConfig,
	})
}

// UnmarshalJSON loads the cache under its write lock and always leaves a
// usable, non-nil map behind.
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
	c.stateVersion = dto.StateVersion
	c.daemonConfig = dto.DaemonConfig
	return nil
}
