// Package paths resolves the filesystem locations nokkud owns.
package paths

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	configFilename      = "config.json"
	cacheFilename       = "cache.json"
	signerStateFilename = "state.json"
	hostSignerFilename  = "ssh_host_signer.json"
	userCAFilename      = "nokku_ca.pub"
	retiredCAFilename   = "nokku_ca.previous.pub"
	recordsDir          = "recordings"
	auditDir            = "audit"
	hostKeyName         = "ssh_host_ecdsa_key"
)

func dataDir() string {
	if dir := os.Getenv("NOKKUD_DATA_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/nokkud"
}

func RecordsDir() string { return filepath.Join(dataDir(), recordsDir) }

func AuditDir() string { return filepath.Join(dataDir(), auditDir) }

func ConfigFile() string { return filepath.Join(dataDir(), configFilename) }

func CacheFile() string { return filepath.Join(dataDir(), cacheFilename) }

func SignerStateFile() string { return filepath.Join(dataDir(), signerStateFilename) }

func UserCAFile() string { return filepath.Join(dataDir(), userCAFilename) }

func RetiredCAFile() string { return filepath.Join(dataDir(), retiredCAFilename) }

// HostSignerStateFile is the tpm.Signer state backing the host identity.
func HostSignerStateFile() string { return filepath.Join(dataDir(), hostSignerFilename) }

// HostKeyPub is the public half of the host identity, signed into a host
// certificate by the sync. The key is ECDSA P-256 in both storage modes.
func HostKeyPub() string { return filepath.Join(dataDir(), hostKeyName+".pub") }

// HostKeyCert is the host certificate the embedded SSH server presents.
func HostKeyCert() string { return filepath.Join(dataDir(), hostKeyName+"-cert.pub") }

// Verify creates the owned directories with 0700 perms. MkdirAll leaves an
// existing directory's mode alone, so the mode is applied explicitly.
func Verify() error {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", dir, err)
	}
	//nolint:gosec // G302: a directory needs the execute bit to be traversable
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("cannot secure directory %s: %w", dir, err)
	}
	if err := os.MkdirAll(RecordsDir(), 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", RecordsDir(), err)
	}
	// Audit dir creation must not fail the daemon when the data dir is not
	// writable (e.g. a read-only first boot). The audit sink is optional.
	if err := os.MkdirAll(AuditDir(), 0o700); err != nil {
		slog.Debug("cannot create audit directory", "error", err)
	}
	return nil
}

// Cleanup removes the application state owned by these paths.
func Cleanup() {
	if err := os.RemoveAll(dataDir()); err != nil {
		slog.Error("remove data directory", "error", err)
	}
}
