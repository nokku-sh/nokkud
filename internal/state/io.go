package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/nokku-sh/nokkud/internal/util"
)

// loadJSON reads a JSON file into v. A missing file is not an error. A
// corrupted one is removed and corrupt is invoked so the caller can drop to a
// clean state instead of a half-loaded one. Both Config and Cache use it so
// the missing-file and corruption handling stays identical and lives in one
// place.
func loadJSON(path string, v any, corrupt func()) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err = json.Unmarshal(data, v); err != nil {
		corrupt()
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			slog.Warn("remove corrupted state file", "path", path, "error", rmErr)
		}
		return nil
	}
	return nil
}

// saveJSON marshals v and atomically writes it with the given permissions,
// skipping unchanged content.
func saveJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing state: %w", err)
	}
	if err = util.WriteIfChanged(path, data, perm); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	return nil
}
