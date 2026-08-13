// Package util holds small shared helpers: atomic file writes, safe
// username validation and string sanitization used across the daemon.
package util

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile atomically writes data to a file with the given mode. On
// non-Windows platforms the mode is applied before the rename.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	if filename == "" {
		return fmt.Errorf("empty filename")
	}

	filename = filepath.Clean(filename)
	if fi, err := os.Stat(filename); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", filename)
	}

	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = f.Write(data); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err = f.Chmod(perm); err != nil {
			return err
		}
	}

	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	err = os.Rename(tmpName, filename)
	return err
}

// WriteIfChanged atomically writes only when data differs from disk;
// reports whether it wrote.
func WriteIfChanged(filename string, data []byte, perm os.FileMode) error {
	filename = filepath.Clean(filename)
	fi, err := os.Stat(filename)

	if err == nil {
		// Fast path: if sizes differ, the content definitely differs
		if fi.Size() != int64(len(data)) {
			return WriteFile(filename, data, perm)
		}

		// Slow path: sizes match, so we must compare the actual bytes
		var existingData []byte
		existingData, err = os.ReadFile(filename)
		if err == nil && bytes.Equal(existingData, data) {
			return nil // Data is identical, do nothing
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return WriteFile(filename, data, perm)
}
