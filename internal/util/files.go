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

// WriteIfChanged atomically writes data only when it differs from what is
// already on disk.
func WriteIfChanged(filename string, data []byte, perm os.FileMode) error {
	if filename == "" {
		return fmt.Errorf("empty filename")
	}

	filename = filepath.Clean(filename)
	if fi, err := os.Stat(filename); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", filename)
		}
		// Fast path. If sizes differ, the content definitely differs.
		if fi.Size() != int64(len(data)) {
			return writeAtomic(filename, data, perm)
		}
		// Slow path. Sizes match, so compare the actual bytes.
		var existing []byte
		if existing, err = os.ReadFile(filename); err == nil && bytes.Equal(existing, data) {
			return nil // Data is identical, do nothing.
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(filename, data, perm)
}

// writeAtomic writes data to a temp file and renames it over filename. On
// non-Windows platforms the mode is applied before the rename.
func writeAtomic(filename string, data []byte, perm os.FileMode) error {
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

	if err = os.Rename(tmpName, filename); err != nil {
		return err
	}

	// Fsync the parent directory so the rename itself is durable across a
	// crash. Best-effort: the file is already in place, and some filesystems
	// (and Windows) cannot sync a directory.
	if runtime.GOOS != "windows" {
		if dir, derr := os.Open(filepath.Dir(filename)); derr == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
	}
	return nil
}
