package state

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokkud/internal/paths"
)

func newTestDataDir(t *testing.T) {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewConfig()
	c.WorkspaceID = "ws-1"
	c.TargetID = "tgt-1"
	c.DaemonID = "daemon-1"
	c.APIURL = "https://api.example.com"
	c.SSHAddr = ":4022"

	must.NoError(c.Save())

	loaded := NewConfig()
	must.NoError(loaded.Load())
	is.Equal("ws-1", loaded.WorkspaceID)
	is.Equal("tgt-1", loaded.TargetID)
	is.Equal("daemon-1", loaded.DaemonID)
	is.Equal("https://api.example.com", loaded.APIURL)
	is.Equal(":4022", loaded.SSHAddr)
}

func TestConfigLoadMissingFileIsNotAnError(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)

	c := NewConfig()
	is.NoError(c.Load())
}

func TestConfigLoadCorruptedClearsAndRemoves(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewConfig()
	c.WorkspaceID = "ws-1"
	must.NoError(c.Save())
	must.NoError(os.WriteFile(paths.ConfigFile(), []byte("{not json"), 0o600))

	loaded := NewConfig()
	must.NoError(loaded.Load())
	is.Empty(loaded.WorkspaceID)

	_, err := os.Stat(paths.ConfigFile())
	is.True(os.IsNotExist(err))
}

func TestConfigClearKeepsSaveTarget(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewConfig()
	c.WorkspaceID = "ws-1"
	c.Clear()

	is.Empty(c.WorkspaceID)
	must.NoError(c.Save())
	_, err := os.Stat(paths.ConfigFile())
	is.NoError(err)
}

func TestConfigSaveSkipsUnchanged(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewConfig()
	c.WorkspaceID = "ws-1"
	must.NoError(c.Save())
	fi, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.NoError(c.Save())
	fi2, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.Equal(fi.ModTime(), fi2.ModTime())
}

func TestConfigSaveWritesWithPrivatePerms(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	c := NewConfig()
	c.WorkspaceID = "ws-1"
	must.NoError(c.Save())
	fi, err := os.Stat(paths.ConfigFile())
	must.NoError(err)
	is.Equal(os.FileMode(0o600), fi.Mode().Perm())
}

func TestConfigFileNeverContainsPaths(t *testing.T) {
	newTestDataDir(t)
	is := assert.New(t)
	must := require.New(t)

	dataDir := os.Getenv("NOKKUD_DATA_DIR")
	c := NewConfig()
	c.WorkspaceID = "ws-1"
	must.NoError(c.Save())
	data, err := os.ReadFile(paths.ConfigFile())
	must.NoError(err)

	// The data dir must not leak into the serialized enrollment state,
	// which is shared with the control plane.
	is.NotContains(string(data), dataDir)
}
