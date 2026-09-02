package recording

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sysutil"
	"github.com/nokku-sh/nokkud/internal/util"
)

const (
	// MaxSize is the maximum uncompressed size of a recording.
	MaxSize = 50 << 20
	// MaxIdleTime is the maximum gap between events recorded in the cast.
	MaxIdleTime = 2 * time.Second
	// maxFlushInterval bounds how long compressed data sits in the gzip
	// buffer. A crash loses at most this much of the tail of a recording.
	maxFlushInterval = 100 * time.Millisecond
)

// Header is the asciicast v3 metadata block written first in a recording.
type Header struct {
	Version   int    `json:"version"`
	Term      Term   `json:"term"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Title     string `json:"title,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// Term is the terminal info block of an asciicast v3 header.
type Term struct {
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
	Type string `json:"type,omitempty"`
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

// Recorder writes session events to a single gzipped asciicast v3 file.
type Recorder struct {
	mu        sync.Mutex
	cw        *countingWriter
	gw        *gzip.Writer
	enc       *json.Encoder
	sink      io.WriteCloser
	lastEvent time.Time
	// msCarry carries the fractional-millisecond rounding error from one
	// interval to the next, so the written intervals sum to the real time
	// even after each is rounded to the nearest millisecond.
	msCarry float64
	// exitCode is the session's exit status written last, so the x event
	// stays the final event.
	exitCode *int
	dirty    bool
	done     chan struct{}
	closed   bool
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
		Version: 3,
		Term: Term{
			Cols: opts.Width,
			Rows: opts.Height,
			Type: term,
		},
		Timestamp: time.Now().Unix(),
		Title:     opts.Title,
		SessionID: opts.SessionID,
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

	r.emit(eventType, data)
}

// emit writes one event line. Caller holds r.mu and has checked not closed.
func (r *Recorder) emit(eventType string, data []byte) {
	// asciicast v3 timestamps are intervals from the previous event. Real
	// idle gaps longer than MaxIdleTime are clamped so playback does not
	// dwell on terminal inactivity, matching the historical behavior.
	now := time.Now()
	gap := min(now.Sub(r.lastEvent), MaxIdleTime)
	r.lastEvent = now

	encodedData := marshalEventData(string(data))

	line := fmt.Sprintf("[%s, %q, %s]\n", r.roundInterval(gap), eventType, encodedData)

	if _, err := r.gw.Write([]byte(line)); err != nil {
		slog.Error("write recording event", "error", err)
	}
	r.dirty = true
}

// marshalEventData encodes a string as JSON without escaping <, >, and &,
// matching the header encoder, so terminal output (pipes, redirects, Go
// operators) stays readable in the raw cast.
func marshalEventData(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return []byte(`""`)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// roundInterval renders a gap as a millisecond-precision interval, carrying
// the rounding error into the next event (error diffusion) so the sum of the
// written intervals tracks the real time instead of drifting.
func (r *Recorder) roundInterval(gap time.Duration) string {
	r.msCarry += gap.Seconds() * 1000
	ms := int64(math.Round(r.msCarry))
	r.msCarry -= float64(ms)
	return fmt.Sprintf("%d.%03d", ms/1000, ms%1000)
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

// RecordExit records the session's exit status in an exit ("x") event. It is
// written as the last event during Close, after any held redaction tail.
func (r *Recorder) RecordExit(status int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.exitCode = new(status)
}

func (r *Recorder) closeLocked() {
	if r.closed {
		return
	}
	r.closed = true
	close(r.done)

	// The exit status lands before the gzip footer, so the x event stays
	// the final event.
	if r.exitCode != nil {
		r.emit("x", []byte(strconv.Itoa(*r.exitCode)))
	}

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
