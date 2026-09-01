// Package audit appends structured security events as JSON lines, with
// size-based rotation and age-based retention.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nokku-sh/nokkud/internal/util"
)

// EventType enumerates the kinds of security events emitted.
type EventType string

const (
	EventAuthSuccess  EventType = "auth_success"
	EventAuthFailure  EventType = "auth_failure"
	EventSessionStart EventType = "session_start"
	EventSessionEnd   EventType = "session_end"
	EventCommand      EventType = "command"
	EventForward      EventType = "forward"
)

const (
	// MaxFileSize rotates to a new file after this many bytes.
	MaxFileSize = 10 << 20
	// MaxAge retains files younger than this.
	MaxAge = 30 * 24 * time.Hour
	// MaxTotalSize caps the total on-disk size of audit files.
	MaxTotalSize = 1 << 30
	// maxQueuedEvents bounds the events waiting for the writer goroutine.
	// When the queue is full, Emit blocks: security events must never be
	// dropped, so backpressure reaches the caller instead.
	maxQueuedEvents = 1024
)

// Event is a single audit record.
type Event struct {
	Time      time.Time       `json:"time"`
	Type      EventType       `json:"type"`
	User      string          `json:"user,omitempty"`
	Remote    string          `json:"remote,omitempty"`
	Client    string          `json:"client,omitempty"`
	Principal string          `json:"principal,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	Command   string          `json:"command,omitempty"`
	Target    string          `json:"target,omitempty"`
	ExitCode  int             `json:"exit_code,omitempty"`
	Error     string          `json:"error,omitempty"`
	Extra     json.RawMessage `json:"extra,omitempty"`
}

// item is one queued event.
type item struct {
	ev Event
}

// Sink appends events to a rotation-managed JSONL log. Emit hands events
// to a single writer goroutine, so disk I/O never runs on the caller's
// (auth or session) goroutine. The queue is drained on Close.
type Sink struct {
	dir  string
	ch   chan item
	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once

	// Written only by the writer goroutine.
	file *os.File
	size int64
}

// New opens the audit sink under dir, creating it. Returns a nil,
// error-free sink when the dir cannot be prepared so callers can ignore
// audit failures.
func New(dir string) (*Sink, error) {
	if dir == "" {
		return nil, errors.New("audit: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	s := &Sink{
		dir:  dir,
		ch:   make(chan item, maxQueuedEvents),
		done: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Emit queues one event for the writer goroutine. It blocks while the
// queue is full so no event is ever dropped; after Close it returns
// without queueing.
func (s *Sink) Emit(ev Event) {
	if s == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	select {
	case s.ch <- item{ev: ev}:
	case <-s.done:
	}
}

// Close stops accepting events, drains the queue and closes the current
// audit file. Safe to call more than once and concurrently with Emit.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.done)
		s.wg.Wait()
	})
	return nil
}

// run is the single writer goroutine. It owns the audit file, rotation and
// retention until done is closed, then drains the queue and exits.
func (s *Sink) run() {
	defer s.wg.Done()

	// The log file is opened lazily on the first event.
	s.enforceRetention()
	for {
		select {
		case it := <-s.ch:
			s.handleItem(it)
		case <-s.done:
			s.drain()
			if s.file != nil {
				_ = s.file.Close()
			}
			return
		}
	}
}

// drain writes every event queued before done was closed.
func (s *Sink) drain() {
	for {
		select {
		case it := <-s.ch:
			s.handleItem(it)
		default:
			return
		}
	}
}

// handleItem writes one queued event.
func (s *Sink) handleItem(it item) {
	s.write(it.ev)
}

// write appends one event, rotating and enforcing retention as needed.
func (s *Sink) write(ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Debug("audit: marshal event", "error", err)
		return
	}
	data = append(data, '\n')

	if s.file == nil {
		if err = s.rotate(); err != nil {
			slog.Warn("audit: open log", "error", err)
			return
		}
	}

	if s.size+int64(len(data)) > MaxFileSize {
		if err = s.rotate(); err != nil {
			slog.Warn("audit: rotate", "error", err)
			return
		}
	}

	n, err := s.file.Write(data)
	if err != nil {
		slog.Warn("audit: write event", "error", err)
		return
	}
	s.size += int64(n)
}

// rotate closes the current file, opens a fresh one and re-enforces retention.
func (s *Sink) rotate() error {
	if s.file != nil {
		_ = s.file.Close()
	}

	// Zero-padded UTC timestamp with nanosecond precision.
	name := filepath.Join(
		s.dir,
		time.Now().UTC().Format("audit-20060102T150405.000000000Z.jsonl"),
	)
	f, err := os.OpenFile(
		name,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0o600,
	) // #nosec G304 - timestamped name
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat: %w", err)
	}
	s.file = f
	s.size = fi.Size()
	s.enforceRetention()
	return nil
}

// enforceRetention removes audit files older than MaxAge and, when the total
// exceeds MaxTotalSize, the oldest files.
func (s *Sink) enforceRetention() {
	matches, err := filepath.Glob(filepath.Join(s.dir, "audit-*.jsonl"))
	if err != nil {
		return
	}
	files := make([]os.FileInfo, 0, len(matches))
	for _, path := range matches {
		var fi os.FileInfo
		fi, err = os.Stat(path)
		if err != nil {
			continue
		}
		files = append(files, fi)
	}
	util.PruneOldest(s.dir, files, MaxAge, MaxTotalSize)
}
