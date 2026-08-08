//go:build windows

package sysutil

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CheckDiskSpace errors when fewer than 5 GiB are free on path's
// filesystem, so recording bails before filling the disk.
func CheckDiskSpace(path string) error {
	var freeBytesAvailableToCaller, totalNumberOfBytes, totalNumberOfFreeBytes uint64

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if err := windows.GetDiskFreeSpaceEx(
		pathPtr,
		&freeBytesAvailableToCaller,
		&totalNumberOfBytes,
		&totalNumberOfFreeBytes,
	); err != nil {
		return fmt.Errorf("GetDiskFreeSpaceEx failed: %w", err)
	}

	if freeBytesAvailableToCaller < 5<<30 {
		return fmt.Errorf("dangerously low disk space: %d bytes free", freeBytesAvailableToCaller)
	}
	return nil
}
