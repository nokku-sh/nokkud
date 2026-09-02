package recording

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

const (
	// MaxTotalSpace limits the total space used by recordings.
	MaxTotalSpace = 1 << 30
	// MaxAge sets the retention period.
	MaxAge = 30 * 24 * time.Hour
)

// EnforceRetention removes old recordings based on time and total space
// constraints.
func EnforceRetention(p paths.Paths) error {
	entries, err := os.ReadDir(p.RecordsDir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			// The recordings dir is a sticky drop-box (no read bit)
			return nil
		}
		return err
	}

	var files []os.FileInfo
	for _, e := range entries {
		// Check for .cast and .cast.gz files.
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

	util.PruneOldest(p.RecordsDir, files, MaxAge, MaxTotalSpace)
	return nil
}

// recordingFilename builds a timestamped, sanitized filename. When a session
// ID is present its first 8 characters are embedded so the recording can be
// correlated with audit events by eye as well as through the header.
func recordingFilename(now time.Time, safeLabel, sessionID string) string {
	parts := []string{now.Format("20060102T150405Z"), safeLabel}
	if id := shortSessionID(sessionID); id != "" {
		// The ID must never smuggle path separators into the filename, so
		// sanitize it exactly like the label.
		parts = append(parts, util.ToSnakeCase(id))
	}
	parts = append(parts, strconv.Itoa(os.Getpid()))
	return strings.Join(parts, "-") + ".cast.gz"
}

// shortSessionID trims a session ID to 8 characters for the filename. The
// full ID always lives in the asciicast header.
func shortSessionID(id string) string {
	return id[:min(len(id), 8)]
}
