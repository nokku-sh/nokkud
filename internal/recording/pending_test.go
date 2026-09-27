package recording

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resultSink reports a fixed upload result from Close.
type resultSink struct {
	err  error
	done chan struct{}
}

func (s *resultSink) Write(p []byte) (int, error) { return len(p), nil }

func (s *resultSink) Close() error {
	defer close(s.done)
	return s.err
}

func recordOnce(t *testing.T, sink *resultSink) {
	t.Helper()
	rec, err := New(Options{
		Width: 80, Height: 24, Title: "t", User: "alice",
		SessionID: "0199aaaa-0000-7000-8000-000000000001", Sink: sink,
	})
	require.NoError(t, err)
	rec.RecordOutput([]byte("hello"))
	rec.Close()
	<-sink.done
}

func TestRecorderMarksConfirmedUpload(t *testing.T) {
	dir := newRecordsDir(t)
	recordOnce(t, &resultSink{done: make(chan struct{})})

	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+uploadedSuffix))
		return len(m) == 1
	}, time.Second, 10*time.Millisecond, "confirmed upload was not marked")
}

func TestRecorderKeepsFailedUploadPending(t *testing.T) {
	dir := newRecordsDir(t)
	recordOnce(t, &resultSink{err: errors.New("backend down"), done: make(chan struct{})})

	// Wait until the recorder let go of the file, then it must be pending.
	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
		if len(m) != 1 {
			return false
		}
		_, busy := active.Load(m[0])
		return !busy
	}, time.Second, 10*time.Millisecond)
	m, _ := filepath.Glob(filepath.Join(dir, "*"+uploadedSuffix))
	assert.Empty(t, m, "a failed upload must stay pending")
}

func TestUploadPending(t *testing.T) {
	dir := newRecordsDir(t)
	is := assert.New(t)
	must := require.New(t)
	ts := newTestServer(t)

	recordOnce(t, &resultSink{err: errors.New("backend down"), done: make(chan struct{})})
	require.Eventually(t, func() bool {
		m, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
		if len(m) != 1 {
			return false
		}
		_, busy := active.Load(m[0])
		return !busy
	}, time.Second, 10*time.Millisecond)
	pending, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
	must.Len(pending, 1)
	data, err := os.ReadFile(pending[0])
	must.NoError(err)

	must.NoError(UploadPending(t.Context(), ts.client))

	msgs, opens, _ := ts.snapshot()
	is.Equal(1, opens)
	must.NotEmpty(msgs)
	is.Equal("0199aaaa-0000-7000-8000-000000000001", msgs[0].GetMeta().GetRecordingId())
	is.Equal("alice", msgs[0].GetMeta().GetUsername())
	var sent []byte
	for _, m := range msgs[1 : len(msgs)-1] {
		sent = append(sent, m.GetChunk()...)
	}
	is.Equal(data, sent, "the file must be uploaded byte for byte")
	is.NotNil(msgs[len(msgs)-1].GetFinal())

	left, _ := filepath.Glob(filepath.Join(dir, "*"+castSuffix))
	must.Len(left, 1)
	is.True(strings.HasSuffix(left[0], uploadedSuffix))

	// Nothing is left to upload.
	must.NoError(UploadPending(t.Context(), ts.client))
	_, opens, _ = ts.snapshot()
	is.Equal(1, opens)
}
