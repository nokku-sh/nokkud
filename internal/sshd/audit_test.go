package sshd

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// TestServerAuditEvents verifies auth success/failure, session, and command
// events are emitted to the audit sink.
func TestServerAuditEvents(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	sink := &sliceAudit{}
	addr, closeFn := startTestServerOpts(t, ca, Options{Audit: sink})
	defer closeFn()

	// A successful login + command.
	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err)
	sess, err := client.NewSession()
	must.NoError(err)
	out, err := sess.Output("echo hi")
	must.NoError(err)
	is.Equal("hi\n", string(out))
	_ = sess.Close()
	_ = client.Close()

	// A failed login (wrong principal).
	_, err = dial(t, addr, currentUser(t), userCert(t, ca, "some-other-principal"))
	must.Error(err, "login with wrong principal unexpectedly succeeded")

	types := sink.types()
	for _, want := range []audit.EventType{
		audit.EventAuthSuccess,
		audit.EventAuthFailure,
		audit.EventSessionStart,
		audit.EventSessionEnd,
		audit.EventCommand,
	} {
		is.True(containsEvent(types, want), "missing audit event %q in %v", want, types)
	}
}

// TestAuditSinkFile verifies the JSONL audit sink writes parseable events.
func TestAuditSinkFile(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	dir := t.TempDir()
	s, err := audit.New(filepath.Join(dir, "audit"))
	must.NoError(err)
	defer s.Close()

	s.Emit(audit.Event{Type: audit.EventAuthSuccess, User: "bob", Principal: "p1"})
	s.Emit(audit.Event{Type: audit.EventSessionStart, User: "bob"})
	must.NoError(s.Close())

	matches, err := filepath.Glob(filepath.Join(dir, "audit", "audit-*.jsonl"))
	must.NoError(err)
	is.Len(matches, 1)
	f, err := os.Open(matches[0])
	must.NoError(err)
	defer f.Close()
	var events []audit.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev audit.Event
		must.NoError(json.Unmarshal(sc.Bytes(), &ev))
		events = append(events, ev)
	}
	must.NoError(sc.Err())
	is.Len(events, 2)
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
