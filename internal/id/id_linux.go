//go:build linux

package id

import (
	"errors"
	"os"
	"strings"
)

func machineID() (string, error) {
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(string(data)))
		if id == "" || isBlankMachineID(id) {
			continue
		}
		return id, nil
	}

	return "", errors.New("machine-id not found")
}

// isBlankMachineID reports whether id is the placeholder systemd writes in
// containers and VMs without a real machine ID (all zeros or the literal
// "uninitialized"). Such an ID is not unique, so it must never be used to
// derive the signing key.
func isBlankMachineID(id string) bool {
	return id == "uninitialized" || strings.Trim(id, "0") == ""
}
