package state

import (
	"os"
	"sync"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

func TestCacheRejectsInvalidPrincipals(t *testing.T) {
	t.Parallel()
	c := NewCache()
	c.Replace(map[string][]string{
		"../../etc": {"uuid-1"},
		"0start":    {"uuid-1"},
		"":          {"uuid-1"},
	}, nil, 0)

	if c.HasUUID("../../etc", "uuid-1") {
		t.Fatal("invalid principal added via Replace")
	}
	if c.HasUUID("0start", "uuid-1") {
		t.Fatal("invalid principal added via Replace")
	}
	if c.HasUUID("", "uuid-1") {
		t.Fatal("empty principal added")
	}
}

func TestCacheReplaceCopiesInput(t *testing.T) {
	t.Parallel()
	c := NewCache()

	uuids := []string{"uuid-1", "uuid-2"}
	c.Replace(map[string][]string{"alice": uuids}, nil, 0)
	uuids[0] = "mutated"

	got := c.GetUUIDs("alice")
	if len(got) != 2 || got[0] != "uuid-1" {
		t.Fatalf("Replace aliased its input: %v", got)
	}
}

func TestCacheGetUUIDsReturnsCopy(t *testing.T) {
	t.Parallel()
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1", "uuid-2"}}, nil, 0)

	got := c.GetUUIDs("alice")
	got[0] = "mutated"

	if c.HasUUID("alice", "uuid-1") != true {
		t.Fatal("mutating the returned slice changed the cache")
	}
	if c.HasUUID("alice", "mutated") {
		t.Fatal("mutated uuid leaked into the cache")
	}
}

func TestCacheHasUUID(t *testing.T) {
	t.Parallel()
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)

	if !c.HasUUID("alice", "uuid-1") {
		t.Fatal("HasUUID = false for stored uuid")
	}
	if c.HasUUID("alice", "uuid-2") {
		t.Fatal("HasUUID = true for unknown uuid")
	}
	if c.HasUUID("bob", "uuid-1") {
		t.Fatal("HasUUID = true for unknown principal")
	}
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	c := NewCache()
	c.Replace(map[string][]string{
		"alice": {"uuid-1", "uuid-2"},
		"bob":   {"uuid-3"},
	}, nil, 0)
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := NewCache()
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.HasUUID("alice", "uuid-1") || !loaded.HasUUID("bob", "uuid-3") {
		t.Fatalf("loaded cache lost data: alice=%v bob=%v",
			loaded.GetUUIDs("alice"), loaded.GetUUIDs("bob"))
	}
}

func TestCacheLoadMissingFileIsNotAnError(t *testing.T) {
	newTestDataDir(t)
	c := NewCache()
	if err := c.Load(); err != nil {
		t.Fatalf("Load on missing file: %v, want nil", err)
	}
}

func TestCacheDaemonConfigRoundTrip(t *testing.T) {
	newTestDataDir(t)
	c := NewCache()
	record := true
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{
		RecordSessions: &record,
	})
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := NewCache()
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.RecordSessions() {
		t.Fatal("RecordSessions lost in round trip")
	}
	if !loaded.HasUUID("alice", "uuid-1") {
		t.Fatal("principals lost in round trip")
	}
}

func TestCacheClearDropsSyncedConfig(t *testing.T) {
	t.Parallel()
	record := true
	c := NewCache()
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{RecordSessions: &record})
	if !c.RecordSessions() {
		t.Fatal("RecordSessions not set")
	}
	c.Clear()
	if c.RecordSessions() {
		t.Fatal("Clear left synced config behind")
	}
}

func TestCacheLoadCorruptedClearsAndRemoves(t *testing.T) {
	newTestDataDir(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(paths.CacheFile(), []byte("{not json"), 0o640); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}

	loaded := NewCache()
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load on corrupted cache: %v, want nil", err)
	}
	if loaded.HasUUID("alice", "uuid-1") {
		t.Fatal("corrupted cache left stale auth data behind")
	}
	if _, err := os.Stat(paths.CacheFile()); !os.IsNotExist(err) {
		t.Fatalf("corrupted cache file was not removed: %v", err)
	}
}

func TestCacheClear(t *testing.T) {
	t.Parallel()
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	c.Clear()

	if c.HasUUID("alice", "uuid-1") {
		t.Fatal("Clear left auth data behind")
	}
	// Clearing must not leave a nil map behind. Subsequent writes must work.
	c.Replace(map[string][]string{"bob": {"uuid-2"}}, nil, 0)
	if !c.HasUUID("bob", "uuid-2") {
		t.Fatal("write after Clear failed")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	c := NewCache()

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for range 200 {
				principal := "user"
				if n%2 == 0 {
					principal = "user2"
				}
				c.Replace(map[string][]string{
					principal: {"uuid-1", "uuid-2"},
					"other":   {"uuid-3"},
				}, nil, 0)
				_ = c.HasUUID(principal, "uuid-1")
				_ = c.GetUUIDs("other")
			}
		}(i)
	}
	wg.Wait()

	// No data corruption after concurrent access.
	if !c.HasUUID("user", "uuid-1") && !c.HasUUID("user2", "uuid-1") {
		t.Fatal("concurrent access lost principals")
	}
}

func TestCacheReplace(t *testing.T) {
	t.Parallel()
	c := NewCache()

	// Pre-existing state must be fully replaced, not merged.
	c.Replace(map[string][]string{"stale": {"uuid-old"}}, nil, 0)

	c.Replace(
		map[string][]string{
			"alice":     {"uuid-1", "uuid-2"},
			"../../etc": {"uuid-evil"}, // invalid, must be skipped
		},
		&nokkuv1.DaemonConfig{RecordSessions: new(true)},
		7,
	)

	if c.HasUUID("stale", "uuid-old") {
		t.Fatal("Replace merged instead of replacing")
	}
	if got := c.GetUUIDs("alice"); len(got) != 2 || got[0] != "uuid-1" {
		t.Fatalf("GetUUIDs(alice) = %v", got)
	}
	if c.HasUUID("../../etc", "uuid-evil") {
		t.Fatal("invalid principal must be skipped")
	}
	if c.GetStateVersion() != 7 {
		t.Fatalf("state version = %d, want 7", c.GetStateVersion())
	}
	if !c.RecordSessions() {
		t.Fatal("daemon config lost in Replace")
	}

	// Replacing with an empty map must yield an empty map, not nil.
	c.Replace(nil, nil, 0)
	if c.principals == nil {
		t.Fatal("Replace left a nil principal map")
	}
}
