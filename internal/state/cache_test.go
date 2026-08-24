package state

import (
	"os"
	"sync"
	"testing"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

func TestCacheAddUUIDDedups(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))
	c.AddUUID("alice", "uuid-1")
	c.AddUUID("alice", "uuid-1")
	c.AddUUID("alice", "uuid-2")

	got := c.GetUUIDs("alice")
	if len(got) != 2 || got[0] != "uuid-1" || got[1] != "uuid-2" {
		t.Fatalf("GetUUIDs = %v, want [uuid-1 uuid-2]", got)
	}
}

func TestCacheRejectsInvalidPrincipals(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))
	c.AddUUID("../../etc", "uuid-1")
	c.SetUUIDs("0start", []string{"uuid-1"})
	c.AddUUID("", "uuid-1")

	if c.HasUUID("../../etc", "uuid-1") {
		t.Fatal("invalid principal added via AddUUID")
	}
	if c.HasUUID("0start", "uuid-1") {
		t.Fatal("invalid principal added via SetUUIDs")
	}
	if c.HasUUID("", "uuid-1") {
		t.Fatal("empty principal added")
	}
}

func TestCacheSetUUIDsCopiesInput(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))

	uuids := []string{"uuid-1", "uuid-2"}
	c.SetUUIDs("alice", uuids)
	uuids[0] = "mutated"

	got := c.GetUUIDs("alice")
	if len(got) != 2 || got[0] != "uuid-1" {
		t.Fatalf("SetUUIDs aliased its input: %v", got)
	}
}

func TestCacheGetUUIDsReturnsCopy(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))
	c.SetUUIDs("alice", []string{"uuid-1", "uuid-2"})

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
	c := NewCache(newTestPaths(t))
	c.AddUUID("alice", "uuid-1")

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
	t.Parallel()
	p := newTestPaths(t)
	c := NewCache(p)
	c.SetUUIDs("alice", []string{"uuid-1", "uuid-2"})
	c.AddUUID("bob", "uuid-3")
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := NewCache(p)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.HasUUID("alice", "uuid-1") || !loaded.HasUUID("bob", "uuid-3") {
		t.Fatalf("loaded cache lost data: alice=%v bob=%v",
			loaded.GetUUIDs("alice"), loaded.GetUUIDs("bob"))
	}
}

func TestCacheLoadMissingFileIsNotAnError(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))
	if err := c.Load(); err != nil {
		t.Fatalf("Load on missing file: %v, want nil", err)
	}
}

func TestCacheDaemonConfigRoundTrip(t *testing.T) {
	t.Parallel()
	p := newTestPaths(t)
	c := NewCache(p)
	record := true
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{
		RecordSessions: &record,
	})
	c.SetUUIDs("alice", []string{"uuid-1"})
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := NewCache(p)
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
	c := NewCache(newTestPaths(t))
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
	t.Parallel()
	p := newTestPaths(t)
	c := NewCache(p)
	c.AddUUID("alice", "uuid-1")
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(p.CacheFile(), []byte("{not json"), 0o640); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}

	loaded := NewCache(p)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load on corrupted cache: %v, want nil", err)
	}
	if loaded.HasUUID("alice", "uuid-1") {
		t.Fatal("corrupted cache left stale auth data behind")
	}
	if _, err := os.Stat(p.CacheFile()); !os.IsNotExist(err) {
		t.Fatalf("corrupted cache file was not removed: %v", err)
	}
}

func TestCacheClear(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))
	c.AddUUID("alice", "uuid-1")
	c.Clear()

	if c.HasUUID("alice", "uuid-1") {
		t.Fatal("Clear left auth data behind")
	}
	// Clearing must not leave a nil map behind. Subsequent writes must work.
	c.AddUUID("bob", "uuid-2")
	if !c.HasUUID("bob", "uuid-2") {
		t.Fatal("AddUUID after Clear failed")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	c := NewCache(newTestPaths(t))

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
				c.SetUUIDs(principal, []string{"uuid-1", "uuid-2"})
				c.AddUUID("other", "uuid-3")
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
