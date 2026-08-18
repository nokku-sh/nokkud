// Package id derives a stable machine fingerprint from the hardware machine
// ID (hostname as fallback). It is used only as the software signing key's
// wrap password and never leaves the machine.
package id

import "os"

// MachineID returns the machine's stable identity, degrading to the hostname
// and then "unknown" when no machine ID is available.
func MachineID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	id, err := machineID()
	if err != nil {
		return hostname
	}

	return id
}
