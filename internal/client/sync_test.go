package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCaMatches verifies the cached CA comparison used to detect rollovers:
// content equality, whitespace tolerance, and the missing-file case.
func TestCaMatches(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	t.Setenv("NOKKUD_DATA_DIR", dir)
	caPath := filepath.Join(dir, "nokku_ca.pub")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFw2BPSytSBKCcOmfUWab8JA2uRKsEUO/FtuZACsJccE"

	is.False(caMatches(key), "caMatches must report false when no CA file exists")

	must.NoError(os.WriteFile(caPath, []byte(key+"\n"), 0o644))
	is.True(caMatches(key), "caMatches must match the cached CA")
	is.True(caMatches(key+"\n   "), "caMatches must tolerate surrounding whitespace")
	is.False(caMatches(key[:len(key)-1]+"X"), "caMatches must reject a different CA")
	is.True(caMatches(strings.TrimSpace(key)), "caMatches must ignore whitespace differences")
}
