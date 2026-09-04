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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// newRecordsDir points the daemon paths at a scratch dir and creates the
// recordings directory inside it.
func newRecordsDir(t *testing.T) string {
	t.Helper()
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	dir := paths.RecordsDir()
	must := require.New(t)
	must.NoError(os.MkdirAll(dir, 0o700))
	return dir
}

// TestRecorderCorrelatesSessionID verifies a recording embeds its session ID
// in both the filename and the asciicast header so it can be matched to the
// session's audit events.
func TestRecorderCorrelatesSessionID(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	sessionID := "0123456789abcdef0123456789abcdef"
	rec, err := New(Options{Width: 80, Height: 24, Title: "t", SessionID: sessionID})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hello"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	is.Contains(entries[0].Name(), "01234567")

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	var hdr map[string]any
	must.NoError(json.NewDecoder(gz).Decode(&hdr))
	is.Equal(sessionID, hdr["session_id"])
}

// TestRecorderV3Schema verifies the file carries the v3 term block in the
// header and an exit event as the last line of the event stream.
func TestRecorderV3Schema(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 100, Height: 40, Title: "t", SessionID: "sess-1"})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("hi"))
	rec.RecordExit(7)
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
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
	must.NoError(json.Unmarshal([]byte(lines[0]), &hdr))
	is.Equal(3, hdr.Version)
	is.Equal(100, hdr.Term.Cols)
	is.Equal(40, hdr.Term.Rows)
	is.NotEmpty(hdr.Term.Type)

	last := lines[len(lines)-1]
	var exit []any
	must.NoError(json.Unmarshal([]byte(last), &exit), "last event %q is not valid JSON", last)
	must.Len(exit, 3)
	is.Equal("x", exit[1])
	is.Equal("7", exit[2])
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
	must := require.New(t)
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	lines := strings.Split(strings.TrimSuffix(string(mustReadAll(t, gz)), "\n"), "\n")
	events := make([]eventLine, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var ev []json.RawMessage
		must.NoError(json.Unmarshal([]byte(line), &ev))
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
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	must.NoError(err, "new recorder")
	rec.RecordOutput([]byte("a < b & c > d\n"))
	rec.Close()

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)
	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	raw := string(mustReadAll(t, gz))
	is.Contains(raw, "<")
	is.Contains(raw, "&")
	is.Contains(raw, ">")
	is.NotContains(raw, `\u003c`)
	is.NotContains(raw, `\u0026`)
}

// TestRecorderEscapedUnicodeRoundTrips verifies event data containing a
// literal `\u003c`-style sequence survives marshaling byte for byte. The
// previous HTML-unescape pass corrupted these into invalid JSON, which broke
// parsing of the whole cast.
func TestRecorderEscapedUnicodeRoundTrips(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, SessionID: "s1"})
	must.NoError(err, "new recorder")
	input := `echo '\u003c \u003e \u0026'`
	rec.RecordOutput([]byte(input))
	recRecordAndReadEvents(t, recordsDir, rec, func(events []eventLine) {
		var found bool
		for _, e := range events {
			if string(e.Data) == input {
				found = true
			}
		}
		is.True(found, "event data %q did not round trip", input)
	})
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err, "read gzip")
	return data
}

// TestRecorderFlushesWithoutClose verifies events reach disk while the
// session is still running: the recorder flushes on a bounded interval, so
// a crash loses only the tail, never everything since the last explicit
// flush.
func TestRecorderFlushesWithoutClose(t *testing.T) {
	recordsDir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)

	rec, err := New(Options{Width: 80, Height: 24, Title: "t"})
	must.NoError(err, "new recorder")
	defer rec.Close()

	rec.RecordOutput([]byte("first"))
	rec.RecordOutput([]byte("second"))

	// The flush interval is 100ms, give the recorder generous slack. The
	// file must already contain the events even though Close never ran.
	time.Sleep(3 * maxFlushInterval)

	entries, err := os.ReadDir(recordsDir)
	must.NoError(err)
	must.Len(entries, 1)

	f, err := os.Open(filepath.Join(recordsDir, entries[0].Name()))
	must.NoError(err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must.NoError(err)
	defer gz.Close()

	data, err := io.ReadAll(gz)
	// An unclosed recording has no gzip footer yet, so the reader reports
	// the data it got plus io.ErrUnexpectedEOF. That is the intended crash
	// behavior: everything up to the last flush stays readable.
	is.True(err == nil || errors.Is(err, io.ErrUnexpectedEOF),
		"read recording before close: %v", err)
	body := string(data)
	is.Contains(body, "first")
	is.Contains(body, "second")
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
