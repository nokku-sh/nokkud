package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditNameRe matches the human-readable UTC timestamp file naming, e.g.
// audit-20260807T135423.351178317Z.jsonl.
var auditNameRe = regexp.MustCompile(`^audit-\d{8}T\d{6}\.\d{9}Z\.jsonl$`)

func TestEmitAndRead(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	dir := t.TempDir()
	s, err := New(dir)
	must.NoError(err)
	defer s.Close()

	s.Emit(Event{Type: EventAuthSuccess, User: "bob", Principal: "p1"})
	s.Emit(Event{Type: EventCommand, User: "bob", Command: "ls"})
	must.NoError(s.Close())

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	must.NoError(err)
	is.Len(matches, 1)

	f, err := os.Open(matches[0])
	must.NoError(err)
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		must.NoError(json.Unmarshal(sc.Bytes(), &ev))
		events = append(events, ev)
	}
	must.NoError(sc.Err())
	is.Len(events, 2)
	is.Equal(EventAuthSuccess, events[0].Type)
	is.Equal("bob", events[0].User)
	is.Equal("ls", events[1].Command)
}

// TestNoEmptyFileOnNew verifies the log file is only created when the first
// event is emitted, so an idle daemon never leaves empty files behind.
func TestNoEmptyFileOnNew(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	dir := t.TempDir()
	s, err := New(dir)
	must.NoError(err)
	defer s.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	must.NoError(err)
	is.Empty(matches)

	s.Emit(Event{Type: EventAuthSuccess, User: "bob"})
	s.Close()
	matches, err = filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	must.NoError(err)
	is.Len(matches, 1)
	is.Regexp(auditNameRe, filepath.Base(matches[0]))
}

// TestEmitDropsWhenQueueFull verifies Emit does not block indefinitely on a
// full queue: it waits emitWait, counts the event as dropped and returns.
func TestEmitDropsWhenQueueFull(t *testing.T) {
	is := assert.New(t)

	s := &Sink{
		ch:       make(chan Event, 1),
		done:     make(chan struct{}),
		emitWait: 0,
	}
	s.ch <- Event{Type: EventCommand}

	start := time.Now()
	s.Emit(Event{Type: EventCommand, Command: "ls"})
	elapsed := time.Since(start)

	is.Equal(int64(1), s.dropped.Load())
	is.Less(elapsed, time.Second)
}

// TestEmitAfterCloseDoesNotQueue verifies a closed sink discards events without
// counting them as drops.
func TestEmitAfterCloseDoesNotQueue(t *testing.T) {
	is := assert.New(t)

	s := &Sink{
		ch:       make(chan Event, 1),
		done:     make(chan struct{}),
		emitWait: 0,
	}
	close(s.done)

	s.Emit(Event{Type: EventCommand})
	is.Zero(s.dropped.Load())
	is.Empty(s.ch)
}

// TestReportDroppedWritesDegradedEvent verifies the writer reports dropped
// events as an audit_degraded line carrying the count.
func TestReportDroppedWritesDegradedEvent(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	dir := t.TempDir()
	s := &Sink{
		dir:      dir,
		ch:       make(chan Event),
		done:     make(chan struct{}),
		emitWait: 0,
	}
	s.Emit(Event{Type: EventCommand, Command: "ls"})
	is.Equal(int64(1), s.dropped.Load())

	s.wg.Add(1)
	go s.run()
	must.NoError(s.Close())

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	must.NoError(err)
	must.Len(matches, 1)

	f, err := os.Open(matches[0])
	must.NoError(err)
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		must.NoError(json.Unmarshal(sc.Bytes(), &ev))
		events = append(events, ev)
	}
	must.NoError(sc.Err())
	must.Len(events, 1)
	is.Equal(EventDegraded, events[0].Type)
	is.Equal("audit queue overflow", events[0].Error)
	is.JSONEq(`{"dropped":1}`, string(events[0].Extra))
}

func TestRotation(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)

	dir := t.TempDir()
	s, err := New(dir)
	must.NoError(err)
	defer s.Close()

	// Emit events with a large valid-JSON payload until a rotation happens.
	// Each event is ~64KB, so MaxFileSize (10MB) needs ~160 events.
	big, err := json.Marshal(map[string]string{"blob": strings.Repeat("x", 64<<10)})
	must.NoError(err)
	payload := json.RawMessage(big)

	for range 300 {
		s.Emit(Event{Type: EventForward, Target: "t", Extra: payload})
	}
	s.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	must.NoError(err)
	is.GreaterOrEqual(len(matches), 2)
}
