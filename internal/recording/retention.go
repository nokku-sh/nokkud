package recording

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

const (
	// maxTotalSpace limits the total space used by recordings.
	maxTotalSpace = 1 << 30
	// maxAge sets the retention period.
	maxAge = 30 * 24 * time.Hour
)

// enforceRetention removes old recordings based on time and total space
// constraints.
func enforceRetention() error {
	recordsDir := paths.RecordsDir()
	entries, err := os.ReadDir(recordsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	var files []os.FileInfo
	for _, e := range entries {
		if e.IsDir() ||
			(!strings.HasSuffix(e.Name(), ".cast") && !strings.HasSuffix(e.Name(), ".cast.gz")) {
			continue
		}
		var info os.FileInfo
		info, err = e.Info()
		if err != nil {
			continue
		}
		files = append(files, info)
	}

	sysutil.PruneOldest(recordsDir, files, maxAge, maxTotalSpace)
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
