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
	"sort"
	"sync"
	"time"
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

// Sink appends events to a rotation-managed JSONL log.
type Sink struct {
	mu   sync.Mutex
	dir  string
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
	s := &Sink{dir: dir}

	// The log file is opened lazily on the first event.
	s.enforceRetention()
	return s, nil
}

// Emit writes one event.
func (s *Sink) Emit(ev Event) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

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

// Close closes the current audit file.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Close()
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
	var files []os.FileInfo
	var total int64
	cutoff := time.Now().Add(-MaxAge)
	for _, path := range matches {
		var fi os.FileInfo
		fi, err = os.Stat(path)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			_ = os.Remove(path)
			continue
		}
		files = append(files, fi)
		total += fi.Size()
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime().Before(files[j].ModTime())
	})
	for total > MaxTotalSize && len(files) > 0 {
		total -= files[0].Size()
		_ = os.Remove(filepath.Join(s.dir, files[0].Name()))
		files = files[1:]
	}
}
