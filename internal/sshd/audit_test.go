package sshd

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// TestServerAuditEvents verifies auth success/failure, session, and command
// events are emitted to the audit sink.
func TestServerAuditEvents(t *testing.T) {
	ca := newTestCA(t)
	sink := &sliceAudit{}
	addr, closeFn := startTestServerOpts(t, ca, Options{Audit: sink})
	defer closeFn()

	// A successful login + command.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out, err := sess.Output("echo hi")
	if err != nil || string(out) != "hi\n" {
		t.Fatalf("exec: %q err=%v", out, err)
	}
	_ = sess.Close()
	_ = client.Close()

	// A failed login (wrong principal).
	if _, err = dial(
		t,
		addr,
		currentUser(t),
		userCert(t, ca, "some-other-principal"),
	); err == nil {
		t.Fatal("login with wrong principal unexpectedly succeeded")
	}

	types := sink.types()
	for _, want := range []audit.EventType{
		audit.EventAuthSuccess,
		audit.EventAuthFailure,
		audit.EventSessionStart,
		audit.EventSessionEnd,
		audit.EventCommand,
	} {
		if !containsEvent(types, want) {
			t.Fatalf("missing audit event %q in %v", want, types)
		}
	}
}

// TestAuditSinkFile verifies the JSONL audit sink writes parseable events.
func TestAuditSinkFile(t *testing.T) {
	dir := t.TempDir()
	s, err := audit.New(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer s.Close()

	s.Emit(audit.Event{Type: audit.EventAuthSuccess, User: "bob", Principal: "p1"})
	s.Emit(audit.Event{Type: audit.EventSessionStart, User: "bob"})
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "audit", "audit-*.jsonl"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("audit files: %v %v", matches, err)
	}
	f, err := os.Open(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []audit.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev audit.Event
		if err = json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("parse: %v", err)
		}
		events = append(events, ev)
	}
	if err = sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
}

type sliceAudit struct {
	events []audit.Event
}

func (s *sliceAudit) Emit(ev audit.Event) {
	s.events = append(s.events, ev)
}

func (s *sliceAudit) types() []audit.EventType {
	var out []audit.EventType
	for _, ev := range s.events {
		out = append(out, ev.Type)
	}
	return out
}

func containsEvent(types []audit.EventType, want audit.EventType) bool {
	return slices.Contains(types, want)
}
