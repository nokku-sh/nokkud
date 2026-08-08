//go:build !windows

package sysutil

import (
	"fmt"
	"syscall"
)

// CheckDiskSpace errors when fewer than 5 GiB are free on path's
// filesystem, so recording bails before filling the disk.
func CheckDiskSpace(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("statfs failed: %w", err)
	}

	if stat.Bsize <= 0 {
		return fmt.Errorf("statfs returned negative block size: %d", stat.Bsize)
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize)
	if freeBytes < 5<<30 {
		return fmt.Errorf("dangerously low disk space: %d bytes free", freeBytes)
	}
	return nil
}
