package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/nokku-sh/mon/fsutil"
)

// loadJSON reads path into v. A missing file is a no-op. A corrupt file is
// discarded and v reset to zero.
func loadJSON[T any](path string, v *T) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err = json.Unmarshal(data, v); err != nil {
		slog.Warn("discarding corrupted file", "path", path, "error", err)
		var zero T
		*v = zero
		// Best effort. A leftover file only means the warning repeats next run.
		_ = os.Remove(path)
	}
	return nil
}

// saveJSON marshals v and atomically writes it with the given permissions,
// skipping unchanged content.
func saveJSON[T any](path string, v T, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing state: %w", err)
	}
	return fsutil.WriteIfChanged(path, data, perm)
}
