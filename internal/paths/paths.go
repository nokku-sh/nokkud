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
	retiredCAFilename   = "nokku_ca.previous.pub"
	recordsDir          = "recordings"
	auditDir            = "audit"

	// The daemon embeds its own SSH server and owns exactly one host key.
	// A TPM-backed ECDSA key when a TPM 2.0 is present, otherwise the
	// on-disk ed25519 key below. The system sshd's keys are never read.
	softwareHostKeyName = "ssh_host_ed25519_key"
	tpmHostKeyName      = "ssh_host_ecdsa_key"
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

// RetiredCAFile returns the path where the previously trusted CA key is kept
// during a rollover. Certificates signed by it stay valid until they expire,
// so the SSH server trusts both files for a grace window after a rollover.
func (p Paths) RetiredCAFile() string {
	return filepath.Join(p.ConfigDir, retiredCAFilename)
}

// SoftwareHostKey returns the on-disk software host key path.
func (p Paths) SoftwareHostKey() string {
	return filepath.Join(p.ConfigDir, softwareHostKeyName)
}

// SoftwareHostKeyPub returns the software host key's public half.
func (p Paths) SoftwareHostKeyPub() string {
	return p.SoftwareHostKey() + ".pub"
}

// SoftwareHostKeyCert returns the software host key's certificate path.
func (p Paths) SoftwareHostKeyCert() string {
	return p.SoftwareHostKey() + "-cert.pub"
}

// TPMHostKeyPub returns the TPM-backed host key's public half. Only this
// file exists on disk. The private half never leaves the TPM.
func (p Paths) TPMHostKeyPub() string {
	return filepath.Join(p.ConfigDir, tpmHostKeyName+".pub")
}

// TPMHostKeyCert returns the TPM-backed host key's certificate path.
func (p Paths) TPMHostKeyCert() string {
	return filepath.Join(p.ConfigDir, tpmHostKeyName+"-cert.pub")
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
	// writable (e.g. a read-only first boot). The audit sink is optional.
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
