package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// auditNameRe matches the human-readable UTC timestamp file naming, e.g.
// audit-20260807T135423.351178317Z.jsonl.
var auditNameRe = regexp.MustCompile(`^audit-\d{8}T\d{6}\.\d{9}Z\.jsonl$`)

func TestEmitAndRead(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer s.Close()

	s.Emit(Event{Type: EventAuthSuccess, User: "bob", Principal: "p1"})
	s.Emit(Event{Type: EventCommand, User: "bob", Command: "ls"})
	if err = s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one audit file, got %v (%v)", matches, err)
	}

	f, err := os.Open(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var events []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		if err = json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal line: %v", err)
		}
		events = append(events, ev)
	}
	if err = sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Type != EventAuthSuccess || events[0].User != "bob" {
		t.Fatalf("first event = %+v", events[0])
	}
	if events[1].Command != "ls" {
		t.Fatalf("second event = %+v", events[1])
	}
}

// TestNoEmptyFileOnNew verifies the log file is only created when the first
// event is emitted, so an idle daemon never leaves empty files behind.
func TestNoEmptyFileOnNew(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no audit file before first event, got %v", matches)
	}

	s.Emit(Event{Type: EventAuthSuccess, User: "bob"})
	s.Close()
	matches, err = filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one audit file after first event, got %v", matches)
	}
	if got := filepath.Base(matches[0]); !auditNameRe.MatchString(got) {
		t.Fatalf("audit file name %q does not match readable format", got)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Emit events with a large valid-JSON payload until a rotation happens.
	// Each event is ~64KB, so MaxFileSize (10MB) needs ~160 events.
	big, err := json.Marshal(map[string]string{"blob": strings.Repeat("x", 64<<10)})
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(big)

	for range 300 {
		s.Emit(Event{Type: EventForward, Target: "t", Extra: payload})
	}
	s.Close()

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) < 2 {
		t.Fatalf("expected rotation to produce multiple files, got %d", len(matches))
	}
}
