// Package paths resolves the filesystem locations nokkud owns. Paths is a
// plain value type so tests can point the app at a scratch directory.
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
	recordsDir          = "recordings"
	auditDir            = "audit"
)

// Paths holds the filesystem locations the application reads and writes.
type Paths struct {
	ConfigDir  string
	RecordsDir string
	AuditDir   string
}

// Default returns the standard paths.
func Default() Paths {
	configDir := configDir()
	return Paths{
		ConfigDir:  configDir,
		RecordsDir: filepath.Join(configDir, recordsDir),
		AuditDir:   filepath.Join(configDir, auditDir),
	}
}

// ConfigFile returns the daemon configuration file path.
func (p Paths) ConfigFile() string {
	return filepath.Join(p.ConfigDir, configFilename)
}

// CacheFile returns the principal cache file path.
func (p Paths) CacheFile() string {
	return filepath.Join(p.ConfigDir, cacheFilename)
}

// SignerStateFile returns the machine signing identity state path.
func (p Paths) SignerStateFile() string {
	return filepath.Join(p.ConfigDir, signerStateFilename)
}

// UserCAFile returns the trusted user CA key path.
func (p Paths) UserCAFile() string {
	return filepath.Join(p.ConfigDir, userCAFilename)
}

// PrivateKeys returns the daemon's SSH host private keys.
func (p Paths) PrivateKeys() ([]string, error) {
	return filepath.Glob(filepath.Join(p.ConfigDir, "ssh_host_*_key"))
}

// Certificates returns the daemon's SSH host certificate paths.
func (p Paths) Certificates() ([]string, error) {
	return filepath.Glob(filepath.Join(p.ConfigDir, "ssh_host_*-cert.pub"))
}

// Verify creates the owned directories and checks that the SSH paths exist.
func (p Paths) Verify() error {
	if err := os.MkdirAll(p.ConfigDir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", p.ConfigDir, err)
	}
	if err := os.MkdirAll(p.RecordsDir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", p.RecordsDir, err)
	}
	// Audit dir creation must not fail the daemon when the config dir is not
	// writable (e.g. a read-only first boot); the audit sink is optional.
	if err := os.MkdirAll(p.AuditDir, 0o700); err != nil {
		slog.Debug("cannot create audit directory", "error", err)
	}
	return nil
}

// Cleanup removes the application state owned by these paths.
func (p Paths) Cleanup() {
	if err := os.RemoveAll(p.ConfigDir); err != nil {
		slog.Error("remove config directory", "error", err)
	}
}

func configDir() string {
	switch runtime.GOOS {
	case "linux":
		return "/var/lib/nokkud"
	case "darwin":
		return "/var/db/nokkud"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Nokkud")
	default:
		return "/var/lib/nokkud"
	}
}
