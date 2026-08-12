// Package recorder captures terminal sessions as gzipped asciicast v2
// files, bounded by size, disk usage and age.
package recorder

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sysutil"
	"github.com/nokku-sh/nokkud/internal/util"
)

const (
	// MaxSize is the maximum uncompressed size of a recording.
	MaxSize = 50 << 20
	// MaxTotalSpace limits the total space used by recordings.
	MaxTotalSpace = 1 << 30
	// MaxAge sets the retention period.
	MaxAge = 30 * 24 * time.Hour
	// MaxIdleTime is the maximum gap between events during playback.
	MaxIdleTime = 2 * time.Second
)

// Header is the asciicast v2 metadata block written first in a recording.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Title     string            `json:"title,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// Options configures a recording; SessionID ties it to audit events.
type Options struct {
	Width     int
	Height    int
	Title     string // stored in the asciicast header
	Label     string // short human-usable label for the filename
	SessionID string // correlates the recording with the session's audit events
}

// Recorder writes session events to a single gzipped asciicast v2 file.
// Record* methods are safe for concurrent use and no-op after Close.
type Recorder struct {
	mu        sync.Mutex
	cw        *countingWriter
	gw        *gzip.Writer
	enc       *json.Encoder
	started   time.Time
	lastEvent time.Time
	closed    bool
}

type countingWriter struct {
	w       *os.File
	written int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.written += int64(n)
	return n, err
}

// New starts a recording under p.RecordsDir, enforcing retention first.
// Returns a nil no-op recorder when disk space is too low.
func New(p paths.Paths, opts Options) (*Recorder, error) {
	if err := sysutil.CheckDiskSpace(p.RecordsDir); err != nil {
		slog.Warn("low disk space, skipping recording", "error", err)
		return nil, nil //nolint:nilnil // intentional: nil recorder is a valid no-op
	}

	label := opts.Title
	if opts.Label != "" {
		label = opts.Label
	}
	safeLabel := util.ToSnakeCase(label)
	filename := recordingFilename(time.Now(), safeLabel, opts.SessionID)

	// The filename is fully self-constructed (timestamp, sanitized label,
	// sanitized session id, pid), so joining it with the records dir carries
	// no traversal risk.
	path := filepath.Join(p.RecordsDir, filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	if err = EnforceRetention(p); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}

	cw := &countingWriter{w: f}
	gw := gzip.NewWriter(cw)
	enc := json.NewEncoder(gw)
	enc.SetEscapeHTML(false)

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}

	if err = enc.Encode(Header{
		Version:   2,
		Width:     opts.Width,
		Height:    opts.Height,
		Timestamp: time.Now().Unix(),
		Title:     opts.Title,
		SessionID: opts.SessionID,
		Env:       map[string]string{"TERM": term},
	}); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write header: %w", err)
	}

	if err = gw.Flush(); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush header: %w", err)
	}

	return &Recorder{
		cw:        cw,
		gw:        gw,
		enc:       enc,
		started:   time.Now(),
		lastEvent: time.Now(),
	}, nil
}

func (r *Recorder) event(eventType string, data []byte) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return
	}

	if r.cw.written >= MaxSize {
		slog.Warn("recording size limit reached, stopping", "size", MaxSize)
		r.closeLocked()
		return
	}

	now := time.Now()
	if gap := now.Sub(r.lastEvent); gap > MaxIdleTime {
		r.started = r.started.Add(gap - MaxIdleTime)
	}
	r.lastEvent = now

	elapsed := time.Since(r.started).Seconds()
	encodedData, err := json.Marshal(string(data))
	if err != nil {
		slog.Error("marshal recording event", "error", err)
		return
	}

	line := fmt.Sprintf("[%f, %q, %s]\n", elapsed, eventType, encodedData)

	if _, err = r.gw.Write([]byte(line)); err != nil {
		slog.Error("write recording event", "error", err)
	}

	_ = r.gw.Flush() // flush after every write survives crash
}

// RecordOutput appends an output ("o") event.
func (r *Recorder) RecordOutput(data []byte) {
	r.event("o", data)
}

// RecordInput appends an input ("i") event.
func (r *Recorder) RecordInput(data []byte) {
	r.event("i", data)
}

// RecordResize appends a resize ("r") event for the new terminal size.
func (r *Recorder) RecordResize(width, height int) {
	r.event("r", fmt.Appendf(nil, "%dx%d", width, height))
}

func (r *Recorder) closeLocked() {
	if r.closed {
		return
	}
	r.closed = true

	if err := r.gw.Close(); err != nil {
		slog.Error("close gzip writer", "error", err)
	}
	if err := r.cw.w.Close(); err != nil {
		slog.Error("close recording file", "error", err)
	}
}

// Close flushes and closes the recording. Safe on a nil recorder.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked()
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
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// EnforceRetention removes old recordings based on time and total space constraints.
func EnforceRetention(p paths.Paths) error {
	entries, err := os.ReadDir(p.RecordsDir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			// The recordings dir is a sticky drop-box (no read bit)
			return nil
		}
		return err
	}

	type recordFile struct {
		path string
		info os.FileInfo
	}

	var files []recordFile
	for _, e := range entries {
		// check for .cast and .cast.gz files
		if e.IsDir() ||
			(!strings.HasSuffix(e.Name(), ".cast") && !strings.HasSuffix(e.Name(), ".cast.gz")) {
			continue
		}
		var info os.FileInfo
		info, err = e.Info()
		if err != nil {
			continue
		}
		files = append(files, recordFile{
			path: filepath.Join(p.RecordsDir, e.Name()),
			info: info,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].info.ModTime().Before(files[j].info.ModTime())
	})

	cutoffTime := time.Now().Add(-MaxAge)
	var totalSize int64
	var keptFiles []recordFile

	for _, f := range files {
		if f.info.ModTime().Before(cutoffTime) {
			if err = os.Remove(f.path); err != nil {
				slog.Warn("remove old recording", "path", f.path, "error", err)
			}
			continue
		}
		keptFiles = append(keptFiles, f)
		totalSize += f.info.Size()
	}

	for _, f := range keptFiles {
		if totalSize <= MaxTotalSpace {
			break
		}
		if err = os.Remove(f.path); err != nil {
			slog.Warn("remove recording for space", "path", f.path, "error", err)
			continue
		}
		totalSize -= f.info.Size()
	}

	return nil
}
