package recorder

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// TestRecorderCorrelatesSessionID verifies a recording embeds its session ID
// in both the filename and the asciicast header so it can be matched to the
// session's audit events.
func TestRecorderCorrelatesSessionID(t *testing.T) {
	p := paths.Paths{ConfigDir: t.TempDir(), RecordsDir: t.TempDir()}
	if err := os.MkdirAll(p.RecordsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	sessionID := "0123456789abcdef0123456789abcdef"
	rec, err := New(p, Options{Width: 80, Height: 24, Title: "t", SessionID: sessionID})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	rec.RecordOutput([]byte("hello"))
	rec.Close()

	entries, err := os.ReadDir(p.RecordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 recording, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Name(), "01234567") {
		t.Fatalf("filename %q does not embed the session id", entries[0].Name())
	}

	f, err := os.Open(filepath.Join(p.RecordsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	var hdr map[string]any
	if err = json.NewDecoder(gz).Decode(&hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if got := hdr["session_id"]; got != sessionID {
		t.Fatalf("header session_id = %v, want %q", got, sessionID)
	}
}

// New returns (nil, nil) when recording is unavailable (e.g. low disk
// space). A nil Recorder must be a safe no-op: sessions rely on it and
// must never panic, including via interface-wrapped nil receivers.
func TestNilRecorderIsNoOp(t *testing.T) {
	t.Parallel()

	var rec *Recorder
	rec.RecordOutput([]byte("out"))
	rec.RecordInput([]byte("in"))
	rec.RecordResize(80, 24)
	rec.Close()
	rec.Close()

	// Through an interface, as the resize watcher receives it. Note the
	// typed-nil trap: this interface is non-nil even though rec is, which
	// is exactly why the methods themselves must be nil-safe.
	var iface interface{ RecordResize(int, int) } = rec
	iface.RecordResize(80, 24)
}
