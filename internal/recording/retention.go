package recording

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
)

const (
	// maxTotalSpace limits the total space used by recordings.
	maxTotalSpace = 1 << 30
	// maxAge sets the retention period.
	maxAge = 30 * 24 * time.Hour
)

// enforceRetention removes recordings older than maxAge, then the oldest ones
// while the rest exceeds maxTotalSpace.
func enforceRetention() error {
	recordsDir := paths.RecordsDir()
	entries, err := os.ReadDir(recordsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)
	var kept []os.FileInfo
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), castSuffix) {
			continue
		}
		var info os.FileInfo
		info, err = e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err = os.Remove(filepath.Join(recordsDir, info.Name())); err != nil {
				slog.Debug("remove expired file", "path", info.Name(), "error", err)
			}
			continue
		}
		kept = append(kept, info)
		total += info.Size()
	}

	slices.SortFunc(kept, func(a, b os.FileInfo) int {
		return a.ModTime().Compare(b.ModTime())
	})
	for total > maxTotalSpace && len(kept) > 0 {
		total -= kept[0].Size()
		if err = os.Remove(filepath.Join(recordsDir, kept[0].Name())); err != nil {
			slog.Debug("remove over-limit file", "path", kept[0].Name(), "error", err)
		}
		kept = kept[1:]
	}
	return nil
}

// recordingPattern builds a timestamped [os.CreateTemp] pattern. The session
// ID correlates the recording with its audit events and is sanitized like the
// label, so it can never smuggle a path separator in.
func recordingPattern(now time.Time, safeLabel, sessionID string) string {
	parts := []string{now.Format("20060102T150405Z"), safeLabel}
	if sessionID != "" {
		parts = append(parts, toSnakeCase(sessionID))
	}
	return strings.Join(parts, "-") + "-*" + castSuffix
}
