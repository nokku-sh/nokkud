// Package audit writes security events as JSON lines with size-based rotation and age-based retention.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nokku-sh/nokkud/internal/util"
)

type EventType string

const (
	EventAuthSuccess  EventType = "auth_success"
	EventAuthFailure  EventType = "auth_failure"
	EventSessionStart EventType = "session_start"
	EventSessionEnd   EventType = "session_end"
	EventCommand      EventType = "command"
	EventForward      EventType = "forward"
	EventDegraded     EventType = "audit_degraded"
)

const (
	// MaxFileSize rotates to a new file after this many bytes.
	MaxFileSize = 10 << 20
	// MaxAge retains files younger than this.
	MaxAge = 30 * 24 * time.Hour
	// MaxTotalSize caps the total on-disk size of audit files.
	MaxTotalSize = 1 << 30
	// maxQueuedEvents bounds the queue feeding the writer goroutine.
	maxQueuedEvents = 1024
	// emitWaitDefault is how long Emit waits for queue space before dropping.
	emitWaitDefault = 2 * time.Second
	// dropReportInterval is how often the writer reports dropped events.
	dropReportInterval = 5 * time.Second
)

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

// Sink writes events to a rotation-managed JSONL log from a single writer
// goroutine, so disk I/O never runs on the caller's auth or session goroutine.
// Emit drops events when the queue stays full past emitWait, and the writer
// goroutine reports the loss as an EventDegraded event.
type Sink struct {
	dir      string
	ch       chan Event
	done     chan struct{}
	emitWait time.Duration
	wg       sync.WaitGroup
	once     sync.Once

	// dropped counts events discarded by Emit. Incremented by callers and
	// drained by the writer goroutine.
	dropped atomic.Int64

	// Written only by the writer goroutine.
	file *os.File
	size int64
}

// New opens the audit sink under dir, creating it.
func New(dir string) (*Sink, error) {
	if dir == "" {
		return nil, errors.New("audit: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	s := &Sink{
		dir:      dir,
		ch:       make(chan Event, maxQueuedEvents),
		done:     make(chan struct{}),
		emitWait: emitWaitDefault,
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// Emit queues one event for the writer goroutine. A full queue waits up to
// emitWait for space, then the event is dropped and counted for the writer to
// report. After Close it returns without queueing.
func (s *Sink) Emit(ev Event) {
	if s == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	select {
	case <-s.done:
		return
	default:
	}
	// Fast path.
	select {
	case s.ch <- ev:
		return
	default:
	}

	t := time.NewTimer(s.emitWait)
	defer t.Stop()
	select {
	case s.ch <- ev:
	case <-s.done:
	case <-t.C:
		s.dropped.Add(1)
	}
}

// Close stops accepting events, drains the queue and closes the audit file.
// Safe to call more than once and concurrently with Emit.
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
// retention, reports dropped events periodically, then drains queued events
// and exits on done.
func (s *Sink) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(dropReportInterval)
	defer ticker.Stop()

	s.enforceRetention()
	for {
		select {
		case ev := <-s.ch:
			s.write(ev)
		case <-ticker.C:
			s.reportDropped()
		case <-s.done:
			s.drain()
			if s.file != nil {
				_ = s.file.Close()
			}
			return
		}
	}
}

// drain writes every event queued before done was closed, then reports drops.
func (s *Sink) drain() {
	for {
		select {
		case ev := <-s.ch:
			s.write(ev)
		default:
			s.reportDropped()
			return
		}
	}
}

// reportDropped writes one EventDegraded event recording how many events Emit
// discarded since the last report. Runs only on the writer goroutine.
func (s *Sink) reportDropped() {
	n := s.dropped.Swap(0)
	if n == 0 {
		return
	}
	s.write(Event{
		Time:  time.Now(),
		Type:  EventDegraded,
		Error: "audit queue overflow",
		Extra: json.RawMessage(fmt.Sprintf(`{"dropped":%d}`, n)),
	})
}

// write appends one event, rotating and enforcing retention as needed.
func (s *Sink) write(ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Debug("marshal audit event", "error", err)
		return
	}
	data = append(data, '\n')

	if s.file == nil {
		if err = s.rotate(); err != nil {
			slog.Warn("open audit log", "error", err)
			return
		}
	}

	if s.size+int64(len(data)) > MaxFileSize {
		if err = s.rotate(); err != nil {
			slog.Warn("rotate audit log", "error", err)
			return
		}
	}

	n, err := s.file.Write(data)
	if err != nil {
		slog.Warn("write audit event", "error", err)
		return
	}
	s.size += int64(n)
}

// rotate closes the current file, opens a fresh one and re-enforces retention.
func (s *Sink) rotate() error {
	if s.file != nil {
		_ = s.file.Close()
	}

	// Zero-padded UTC nanosecond timestamp.
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

// enforceRetention applies MaxAge and MaxTotalSize to the audit files.
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
