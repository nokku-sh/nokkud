// Package id derives a stable, anonymous machine fingerprint from the
// hardware machine ID (hostname as fallback). Hashed so the raw value
// never leaves the machine.
package id

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// MachineID returns a hex HMAC-SHA256 fingerprint of the machine ID.
// Degrades to the hostname, then "unknown".
func MachineID() string {
	hostname, err := os.Hostname() // fallback
	if err != nil {
		return "unknown"
	}

	id, err := machineID()
	if err != nil {
		return hostname
	}

	h := hmac.New(sha256.New, []byte("machine-id"))
	if _, err = h.Write([]byte(id)); err != nil {
		return hostname
	}

	return hex.EncodeToString(h.Sum(nil))
}
