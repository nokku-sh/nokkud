// Package hostcerts manages the host SSH certificate lifecycle: signing
// host keys against the backend and storing certs and the trusted CA
// where the embedded SSH server reads them.
package hostcerts

import "github.com/nokku-sh/nokkud/internal/paths"

// Manager owns the host SSH certificate state.
type Manager struct {
	paths paths.Paths
}

// New returns a Manager for the given paths.
func New(p paths.Paths) *Manager {
	return &Manager{paths: p}
}
