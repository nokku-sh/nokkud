package state

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/paths"
)

func TestCacheRejectsInvalidPrincipals(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{
		"../../etc": {"uuid-1"},
		"0start":    {"uuid-1"},
		"":          {"uuid-1"},
	}, nil, 0)

	is.False(c.HasUUID("../../etc", "uuid-1"))
	is.False(c.HasUUID("0start", "uuid-1"))
	is.False(c.HasUUID("", "uuid-1"))
}

func TestCacheReplaceCopiesInput(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()

	uuids := []string{"uuid-1", "uuid-2"}
	c.Replace(map[string][]string{"alice": uuids}, nil, 0)
	uuids[0] = "mutated"

	is.Equal([]string{"uuid-1", "uuid-2"}, c.GetUUIDs("alice"))
}

func TestCacheGetUUIDsReturnsCopy(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1", "uuid-2"}}, nil, 0)

	got := c.GetUUIDs("alice")
	got[0] = "mutated"

	is.True(c.HasUUID("alice", "uuid-1"))
	is.False(c.HasUUID("alice", "mutated"))
}

func TestCacheHasUUID(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)

	is.True(c.HasUUID("alice", "uuid-1"))
	is.False(c.HasUUID("alice", "uuid-2"))
	is.False(c.HasUUID("bob", "uuid-1"))
}

func TestCacheSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	c.Replace(map[string][]string{
		"alice": {"uuid-1", "uuid-2"},
		"bob":   {"uuid-3"},
	}, nil, 0)
	must.NoError(c.Save())

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.True(loaded.HasUUID("alice", "uuid-1"))
	is.True(loaded.HasUUID("bob", "uuid-3"))
}

func TestCacheLoadMissingFileIsNotAnError(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)

	c := NewCache()
	is.NoError(c.Load())
}

func TestCacheDaemonConfigRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	record := true
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{
		RecordSessions: &record,
	})
	must.NoError(c.Save())

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.True(loaded.RecordSessions())
	is.True(loaded.HasUUID("alice", "uuid-1"))
}

func TestCacheClearDropsSyncedConfig(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	record := true
	c := NewCache()
	c.SetDaemonConfig(&nokkuv1.DaemonConfig{RecordSessions: &record})
	is.True(c.RecordSessions())
	c.Clear()
	is.False(c.RecordSessions())
}

func TestCacheLoadCorruptedClearsAndRemoves(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	must.NoError(c.Save())
	must.NoError(os.WriteFile(paths.CacheFile(), []byte("{not json"), 0o640))

	loaded := NewCache()
	must.NoError(loaded.Load())
	is.False(loaded.HasUUID("alice", "uuid-1"))

	_, err := os.Stat(paths.CacheFile())
	is.True(os.IsNotExist(err))
}

func TestCacheClear(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()
	c.Replace(map[string][]string{"alice": {"uuid-1"}}, nil, 0)
	c.Clear()

	is.False(c.HasUUID("alice", "uuid-1"))

	// Clearing must not leave a nil map behind. Subsequent writes must work.
	c.Replace(map[string][]string{"bob": {"uuid-2"}}, nil, 0)
	is.True(c.HasUUID("bob", "uuid-2"))
}

func TestCacheConcurrentAccess(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	c := NewCache()

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for range 200 {
				principal := "user"
				if i%2 == 0 {
					principal = "user2"
				}
				c.Replace(map[string][]string{
					principal: {"uuid-1", "uuid-2"},
					"other":   {"uuid-3"},
				}, nil, 0)
				_ = c.HasUUID(principal, "uuid-1")
				_ = c.GetUUIDs("other")
			}
		})
	}
	wg.Wait()

	// No data corruption after concurrent access.
	is.True(c.HasUUID("user", "uuid-1") || c.HasUUID("user2", "uuid-1"))
}

func TestCacheReplace(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
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

	is.False(c.HasUUID("stale", "uuid-old"))
	is.Equal([]string{"uuid-1", "uuid-2"}, c.GetUUIDs("alice"))
	is.False(c.HasUUID("../../etc", "uuid-evil"))
	is.EqualValues(7, c.GetStateVersion())
	is.True(c.RecordSessions())

	// Replacing with an empty map must yield an empty map, not nil.
	c.Replace(nil, nil, 0)
	is.NotNil(c.principals)
}
