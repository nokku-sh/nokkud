//go:build linux

package tpm

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

var tpmDevices = []string{"/dev/tpmrm0", "/dev/tpm0"}

func openTPMDevice() (transport.TPMCloser, error) {
	var errs []error
	for _, path := range tpmDevices {
		dev, err := linuxtpm.Open(path)
		if err == nil {
			return dev, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", path, err))
	}
	return nil, errors.Join(errs...)
}
