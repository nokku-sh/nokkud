// Package paths resolves the filesystem locations nokkud owns. Every
// location derives from NOKKUD_DATA_DIR when set, so tests can point the
// daemon at a scratch directory.
package paths

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

const (
	configFilename      = "config.json"
	cacheFilename       = "cache.json"
	signerStateFilename = "state.json"
	userCAFilename      = "nokku_ca.pub"
	retiredCAFilename   = "nokku_ca.previous.pub"
	recordsDir          = "recordings"
	auditDir            = "audit"
	tpmHostKeyName      = "ssh_host_ecdsa_key"
	softwareHostKeyName = "ssh_host_ed25519_key"
)

// dataDir returns the root writable directory for daemon state.
func dataDir() string {
	if dir := os.Getenv("NOKKUD_DATA_DIR"); dir != "" {
		return dir
	}

	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			drive := os.Getenv("SystemDrive")
			if drive == "" {
				drive = "C:"
			}
			pd = filepath.Join(drive, "ProgramData")
		}
		return filepath.Join(pd, "Nokkud")

	case "darwin":
		return "/Library/Application Support/Nokkud"

	default:
		return "/var/lib/nokkud"
	}
}

func RecordsDir() string { return filepath.Join(dataDir(), recordsDir) }

func AuditDir() string { return filepath.Join(dataDir(), auditDir) }

func ConfigFile() string { return filepath.Join(dataDir(), configFilename) }

func CacheFile() string { return filepath.Join(dataDir(), cacheFilename) }

func SignerStateFile() string { return filepath.Join(dataDir(), signerStateFilename) }

func UserCAFile() string { return filepath.Join(dataDir(), userCAFilename) }

func RetiredCAFile() string { return filepath.Join(dataDir(), retiredCAFilename) }

func SoftwareHostKey() string { return filepath.Join(dataDir(), softwareHostKeyName) }

func SoftwareHostKeyPub() string { return SoftwareHostKey() + ".pub" }

func SoftwareHostKeyCert() string { return SoftwareHostKey() + "-cert.pub" }

func TPMHostKeyPub() string { return filepath.Join(dataDir(), tpmHostKeyName+".pub") }

func TPMHostKeyCert() string { return filepath.Join(dataDir(), tpmHostKeyName+"-cert.pub") }

// Verify creates the owned directories and checks that the SSH paths exist.
func Verify() error {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", dir, err)
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
