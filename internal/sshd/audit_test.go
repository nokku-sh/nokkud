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
	dir := t.TempDir()
	sink, err := audit.New(dir)
	must.NoError(err)
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

	must.NoError(sink.Close())
	types := readEventTypes(t, dir)
	for _, want := range []audit.EventType{
		audit.EventAuthSuccess,
		audit.EventAuthFailure,
		audit.EventSessionStart,
		audit.EventSessionEnd,
		audit.EventCommand,
	} {
		is.True(slices.Contains(types, want), "missing audit event %q in %v", want, types)
	}
}

func readEventTypes(t *testing.T, dir string) []audit.EventType {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	require.NoError(t, err)
	var types []audit.EventType
	for _, path := range matches {
		f, openErr := os.Open(path)
		require.NoError(t, openErr)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var ev audit.Event
			require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
			types = append(types, ev.Type)
		}
		_ = f.Close()
	}
	return types
}
