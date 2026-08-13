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
// workspace state version this cache was synced to; the daemon re-syncs
// whenever the backend reports a newer one.
type Cache struct {
	mu           sync.RWMutex
	Principals   map[string][]string `json:"principals"`
	StateVersion int64               `json:"state_version,omitempty"`
	paths        paths.Paths
}

// NewCache returns an empty, ready-to-use cache backed by the given paths.
func NewCache(p paths.Paths) *Cache {
	return &Cache{
		Principals: make(map[string][]string),
		paths:      p,
	}
}

// AddUUID safely adds a unique UUID to a principal.
func (c *Cache) AddUUID(principal string, uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Principals == nil {
		c.Principals = make(map[string][]string)
	}

	if err := util.ValidatePrincipal(principal); err != nil {
		slog.Debug("skipping invalid principal", "principal", principal)
		return
	}

	// Check for uniqueness before appending
	if !slices.Contains(c.Principals[principal], uuid) {
		c.Principals[principal] = append(c.Principals[principal], uuid)
	}
}

// SetUUIDs replaces the entire list of UUIDs for a given principal.
func (c *Cache) SetUUIDs(principal string, uuids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Principals == nil {
		c.Principals = make(map[string][]string)
	}

	if err := util.ValidatePrincipal(principal); err != nil {
		slog.Debug("skipping invalid principal", "principal", principal)
		return
	}

	cacheCopy := make([]string, len(uuids))
	copy(cacheCopy, uuids)

	c.Principals[principal] = cacheCopy
}

// GetUUIDs safely retrieves a copy of the UUIDs for a principal.
func (c *Cache) GetUUIDs(principal string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uuids := c.Principals[principal]
	result := make([]string, len(uuids))
	copy(result, uuids)
	return result
}

// HasUUID reports whether the principal is authorized for the given subject UUID.
func (c *Cache) HasUUID(principal, uuid string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uuids, exists := c.Principals[principal]
	if !exists {
		return false
	}
	return slices.Contains(uuids, uuid)
}

// GetStateVersion returns the state version this cache was synced to.
func (c *Cache) GetStateVersion() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.StateVersion
}

// SetStateVersion records the state version the cache was synced to.
func (c *Cache) SetStateVersion(v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.StateVersion = v
}

func (c *Cache) clearLocked() {
	c.Principals = make(map[string][]string)
	c.StateVersion = 0
}

// Clear drops all cached principals (persisted on the next Save).
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

// Load reads the cache from disk; a missing file is not an error, a
// corrupted one is discarded so the next sync rebuilds it.
func (c *Cache) Load() error {
	data, err := os.ReadFile(c.paths.CacheFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading cache: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if err = json.Unmarshal(data, c); err != nil {
		c.clearLocked()
		if rmErr := os.Remove(c.paths.CacheFile()); rmErr != nil {
			slog.Warn("remove corrupted cache", "error", rmErr)
		}
		return nil
	}

	if c.Principals == nil {
		c.Principals = make(map[string][]string)
	}
	return nil
}

// Save writes the cache atomically, skipping unchanged content.
func (c *Cache) Save() error {
	c.mu.RLock()
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("serializing cache: %w", err)
	}

	if err = util.WriteIfChanged(c.paths.CacheFile(), data, 0o640); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	return nil
}
