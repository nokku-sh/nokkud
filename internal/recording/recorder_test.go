package recording

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// newRecordsDir points the daemon paths at a scratch dir and creates the
// recordings directory inside it.
func newRecordsDir(t *testing.T) string {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	dir := paths.RecordsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRecorderCorrelatesSessionID verifies a recording embeds its session ID
// in both the filename and the asciicast header so it can be matched to the
// session's audit events.
func TestRecorderCorrelatesSessionID(t *testing.T) {
	recordsDir := newRecordsDir(t)

	sessionID := "0123456789abcdef0123456789abcdef"
	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: sessionID})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	rec.RecordOutput([]byte("hello"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 recording, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Name(), "01234567") {
		t.Fatalf("filename %q does not embed the session id", entries[0].Name())
	}

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
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

// TestRecorderV3Schema verifies the file carries the v3 term block in the
// header and an exit event as the last line of the event stream.
func TestRecorderV3Schema(t *testing.T) {
	recordsDir := newRecordsDir(t)

	rec, err := New(Options{Width: 100, Height: 40, Title: "t", SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	rec.RecordOutput([]byte("hi"))
	rec.RecordExit(7)
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 recording, got %d", len(entries))
	}
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	lines := strings.Split(strings.TrimSuffix(string(mustReadAll(t, gz)), "\n"), "\n")

	var hdr struct {
		Version int `json:"version"`
		Term    struct {
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
			Type string `json:"type"`
		} `json:"term"`
	}
	if err = json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr.Version != 3 {
		t.Fatalf("header version = %d, want 3", hdr.Version)
	}
	if hdr.Term.Cols != 100 || hdr.Term.Rows != 40 || hdr.Term.Type == "" {
		t.Fatalf("term block = %+v, want cols=100 rows=40 type set", hdr.Term)
	}

	last := lines[len(lines)-1]
	var exit []any
	if err = json.Unmarshal([]byte(last), &exit); err != nil {
		t.Fatalf("last event %q is not valid JSON: %v", last, err)
	}
	if len(exit) != 3 || exit[1] != "x" || exit[2] != "7" {
		t.Fatalf("last event = %v, want [interval,\"x\",\"7\"]", exit)
	}
}

// eventLine is a decoded asciicast event: [interval, code, data].
type eventLine struct {
	Interval float64
	Code     string
	Data     []byte
}

// recRecordAndReadEvents records the events into rec, closes it, and hands
// the decoded event lines to check.
func recRecordAndReadEvents(
	t *testing.T,
	recordsDir string,
	rec *Recorder,
	check func([]eventLine),
) {
	t.Helper()
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 recording, got %d", len(entries))
	}
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	lines := strings.Split(strings.TrimSuffix(string(mustReadAll(t, gz)), "\n"), "\n")
	events := make([]eventLine, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var ev []json.RawMessage
		if jerr := json.Unmarshal([]byte(line), &ev); jerr != nil {
			t.Fatalf("decode event %q: %v", line, jerr)
		}
		var code string
		var data string
		if len(ev) >= 3 {
			_ = json.Unmarshal(ev[1], &code)
			_ = json.Unmarshal(ev[2], &data)
		}
		events = append(events, eventLine{Code: code, Data: []byte(data)})
	}
	check(events)
}

// TestRecorderNoHTMLEscape verifies event data is marshaled without HTML
// escapes, so terminal output like pipes/angles stays readable in the raw
// cast instead of `\u003c`.
func TestRecorderNoHTMLEscape(t *testing.T) {
	recordsDir := newRecordsDir(t)
	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	rec.RecordOutput([]byte("a < b & c > d\n"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	raw := string(mustReadAll(t, gz))
	if !strings.Contains(raw, "<") || !strings.Contains(raw, "&") || !strings.Contains(raw, ">") {
		t.Fatalf("expected literal angle/ampersand in cast, got %q", raw)
	}
	if strings.Contains(raw, `\u003c`) || strings.Contains(raw, `\u0026`) {
		t.Fatalf("cast contains HTML escapes: %q", raw)
	}
}

// TestRecorderEscapedUnicodeRoundTrips verifies event data containing a
// literal `\u003c`-style sequence survives marshaling byte for byte. The
// previous HTML-unescape pass corrupted these into invalid JSON, which broke
// parsing of the whole cast.
func TestRecorderEscapedUnicodeRoundTrips(t *testing.T) {
	recordsDir := newRecordsDir(t)
	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	input := `echo '\u003c \u003e \u0026'`
	rec.RecordOutput([]byte(input))
	recRecordAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
		var found bool
		for _, e := range events {
			if string(e.Data) == input {
				found = true
			}
		}
		if !found {
			t.Fatalf("event data %q did not round trip", input)
		}
	})
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	return data
}

// TestRecorderFlushesWithoutClose verifies events reach disk while the
// session is still running: the recorder flushes on a bounded interval, so
// a crash loses only the tail, never everything since the last explicit
// flush.
func TestRecorderFlushesWithoutClose(t *testing.T) {
	recordsDir := newRecordsDir(t)

	rec, err := New(Options{Width: 80, Height: 24, Title: "t"})
	if err != nil {
		t.Fatalf("new recorder: %v", err)
	}
	defer rec.Close()

	rec.RecordOutput([]byte("first"))
	rec.RecordOutput([]byte("second"))

	// The flush interval is 100ms, give the recorder generous slack. The
	// file must already contain the events even though Close never ran.
	time.Sleep(3 * maxFlushInterval)

	entries, err := os.ReadDir(recordsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 recording, got %d", len(entries))
	}

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	// An unclosed recording has no gzip footer yet, so the reader reports
	// the data it got plus io.ErrUnexpectedEOF. That is the intended crash
	// behavior: everything up to the last flush stays readable.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read recording before close: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "first") || !strings.Contains(body, "second") {
		t.Fatalf("events not flushed to disk before close: %q", body)
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
