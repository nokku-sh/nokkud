//go:build linux

package id

import (
	"errors"
	"os"
	"strings"
)

func machineID() (string, error) {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(data))
		if id != "" {
			return strings.ToLower(id), nil
		}
	}

	return "", errors.New("machine-id not found")
}
