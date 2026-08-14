// Package state manages the daemon's on-disk enrollment config and the
// cached principal→UUID map that keeps SSH access working offline.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

// Cache is the thread-safe, persisted username→UUID map used for SSH
// access decisions when the backend is unreachable. StateVersion is the
// workspace state version this cache was synced to. The daemon re-syncs
// whenever the backend reports a newer one.
type Cache struct {
	mu           sync.RWMutex
	principals   map[string][]string
	stateVersion int64
	paths        paths.Paths
}

// cacheJSON is the on-disk representation of a Cache. Fields are
// unexported on Cache itself so every access goes through the mutex; the
// JSON shape lives here instead.
type cacheJSON struct {
	Principals   map[string][]string `json:"principals"`
	StateVersion int64               `json:"state_version,omitempty"`
}

// NewCache returns an empty, ready-to-use cache backed by the given paths.
func NewCache(p paths.Paths) *Cache {
	return &Cache{
		principals: make(map[string][]string),
		paths:      p,
	}
}

// AddUUID safely adds a unique UUID to a principal.
func (c *Cache) AddUUID(principal string, uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.principals == nil {
		c.principals = make(map[string][]string)
	}

	if err := util.ValidatePrincipal(principal); err != nil {
		slog.Debug("skipping invalid principal", "principal", principal)
		return
	}

	// Check for uniqueness before appending.
	if !slices.Contains(c.principals[principal], uuid) {
		c.principals[principal] = append(c.principals[principal], uuid)
	}
}

// SetUUIDs replaces the entire list of UUIDs for a given principal.
func (c *Cache) SetUUIDs(principal string, uuids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.principals == nil {
		c.principals = make(map[string][]string)
	}

	if err := util.ValidatePrincipal(principal); err != nil {
		slog.Debug("skipping invalid principal", "principal", principal)
		return
	}

	cacheCopy := make([]string, len(uuids))
	copy(cacheCopy, uuids)

	c.principals[principal] = cacheCopy
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

// SetStateVersion records the state version the cache was synced to.
func (c *Cache) SetStateVersion(v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateVersion = v
}

func (c *Cache) clearLocked() {
	c.principals = make(map[string][]string)
	c.stateVersion = 0
}

// Clear drops all cached principals (persisted on the next Save).
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

// Load reads the cache from disk. A missing file is not an error. A
// corrupted one is discarded so the next sync rebuilds it.
func (c *Cache) Load() error {
	data, err := os.ReadFile(c.paths.CacheFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading cache: %w", err)
	}

	if err = json.Unmarshal(data, c); err != nil {
		c.Clear()
		if rmErr := os.Remove(c.paths.CacheFile()); rmErr != nil {
			slog.Warn("remove corrupted cache", "error", rmErr)
		}
		return nil
	}
	return nil
}

// Save writes the cache atomically, skipping unchanged content.
func (c *Cache) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing cache: %w", err)
	}

	if err = util.WriteIfChanged(c.paths.CacheFile(), data, 0o640); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}

// MarshalJSON serializes the cache under its read lock.
func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(cacheJSON{
		Principals:   c.principals,
		StateVersion: c.stateVersion,
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
	return nil
}
