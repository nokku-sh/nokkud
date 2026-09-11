package util

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// PruneOldest removes files older than maxAge, then oldest-first while the
// remaining total exceeds maxSize. files must be pre-filtered to the ones it owns.
func PruneOldest(dir string, files []os.FileInfo, maxAge time.Duration, maxSize int64) {
	cutoff := time.Now().Add(-maxAge)

	var kept []os.FileInfo
	var total int64
	for _, fi := range files {
		if fi.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, fi.Name())); err != nil {
				slog.Debug("remove expired file", "path", fi.Name(), "error", err)
			}
			continue
		}
		kept = append(kept, fi)
		total += fi.Size()
	}

	slices.SortFunc(kept, func(a, b os.FileInfo) int {
		return a.ModTime().Compare(b.ModTime())
	})
	for total > maxSize && len(kept) > 0 {
		total -= kept[0].Size()
		if err := os.Remove(filepath.Join(dir, kept[0].Name())); err != nil {
			slog.Debug("remove over-limit file", "path", kept[0].Name(), "error", err)
		}
		kept = kept[1:]
	}
}
