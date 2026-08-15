package recording

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	// maxFlushInterval bounds how long compressed data sits in the gzip
	// buffer. A crash loses at most this much of the tail of a recording.
	maxFlushInterval = 100 * time.Millisecond
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

// Options configures a recording. SessionID ties it to audit events.
type Options struct {
	Width     int
	Height    int
	Title     string // stored in the asciicast header
	Label     string // short human-usable label for the filename
	SessionID string // correlates the recording with the session's audit events
	Username  string // recorded in the upload metadata
	// Sink, when set, receives every flushed batch of compressed data in
	// addition to the local file. A failure inside the sink is logged and
	// the sink is dropped: the local file must keep the data either way.
	Sink io.WriteCloser
}

// Recorder writes session events to a single gzipped asciicast v2 file.
type Recorder struct {
	mu        sync.Mutex
	cw        *countingWriter
	gw        *gzip.Writer
	enc       *json.Encoder
	sink      io.WriteCloser
	started   time.Time
	lastEvent time.Time
	dirty     bool
	done      chan struct{}
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
	var w io.Writer = cw
	if opts.Sink != nil {
		// The sink must never take the recording down, a failing sink is
		// disabled and logged, the file keeps receiving everything.
		w = &sinkTee{w: cw, sink: opts.Sink}
	}
	gw := gzip.NewWriter(w)
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

	rec := &Recorder{
		cw:        cw,
		gw:        gw,
		enc:       enc,
		sink:      opts.Sink,
		started:   time.Now(),
		lastEvent: time.Now(),
		done:      make(chan struct{}),
	}
	go rec.flushLoop()
	return rec, nil
}

// sinkTee writes every batch to both the local file and the sink. A sink
// failure is logged once and the sink is dropped, the file is never affected.
type sinkTee struct {
	w    io.Writer
	sink io.WriteCloser
}

func (t *sinkTee) Write(p []byte) (int, error) {
	if t.sink != nil {
		if _, err := t.sink.Write(p); err != nil {
			slog.Warn("recording sink failed, keeping local copy", "error", err)
			_ = t.sink.Close()
			t.sink = nil
		}
	}
	return t.w.Write(p)
}

// flushLoop flushes pending compressed data on a bounded interval while
// the recording is active, so a crash loses at most one interval of the
// tail no matter how the session interleaves bursts and idle time.
func (r *Recorder) flushLoop() {
	ticker := time.NewTicker(maxFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			if r.closed {
				r.mu.Unlock()
				return
			}
			if r.dirty {
				_ = r.gw.Flush()
				r.dirty = false
			}
			r.mu.Unlock()
		case <-r.done:
			return
		}
	}
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
	r.dirty = true
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
	close(r.done)

	// gw.Close flushes pending data and writes the gzip footer, so the
	// file is complete and self-contained after Close. The sink receives
	// the tail through the tee, then Close finalizes the upload.
	if err := r.gw.Close(); err != nil {
		slog.Error("close gzip writer", "error", err)
	}
	if err := r.cw.w.Close(); err != nil {
		slog.Error("close recording file", "error", err)
	}
	if r.sink != nil {
		if err := r.sink.Close(); err != nil {
			slog.Warn("close recording sink", "error", err)
		}
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

	type recordFile struct {
		path string
		info os.FileInfo
	}

	var files []recordFile
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
		files = append(files, recordFile{
			path: filepath.Join(p.RecordsDir, e.Name()),
			info: info,
		})
	}

	slices.SortFunc(files, func(a, b recordFile) int {
		return a.info.ModTime().Compare(b.info.ModTime())
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
