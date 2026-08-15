package recording

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/nacl/box"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// testServer runs an in-memory UploadRecording endpoint and captures every
// received message and stream lifecycle.
type testServer struct {
	mu     sync.Mutex
	msgs   []*nokkuv1.UploadRecordingRequest
	opens  int
	closed int
	client nokkuv1connect.RecordingServiceClient
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ts := &testServer{}
	handler := connect.NewClientStreamHandlerSimple(
		nokkuv1connect.RecordingServiceUploadRecordingProcedure,
		func(_ context.Context, stream *connect.ClientStream[nokkuv1.UploadRecordingRequest]) (*nokkuv1.UploadRecordingResponse, error) {
			ts.mu.Lock()
			ts.opens++
			ts.mu.Unlock()
			for stream.Receive() {
				ts.mu.Lock()
				ts.msgs = append(ts.msgs, stream.Msg())
				ts.mu.Unlock()
			}
			ts.mu.Lock()
			ts.closed++
			ts.mu.Unlock()
			size := int64(123)
			return &nokkuv1.UploadRecordingResponse{SizeBytes: &size}, nil
		},
		// The schema carries the stream type, without it the handler would
		// frame the RPC as unary and never read the body.
		connect.WithSchema(
			nokkuv1.File_nokku_v1_recordings_proto.Services().
				ByName("RecordingService").
				Methods().
				ByName("UploadRecording"),
		),
	)
	mux := http.NewServeMux()
	mux.Handle(nokkuv1connect.RecordingServiceUploadRecordingProcedure, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		// Close client connections first: httptest.Close waits for
		// keep-alive connections and would block on a live one.
		srv.CloseClientConnections()
		srv.Close()
	})
	ts.client = nokkuv1connect.NewRecordingServiceClient(srv.Client(), srv.URL)
	return ts
}

func (ts *testServer) snapshot() (msgs []*nokkuv1.UploadRecordingRequest, opens, closed int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]*nokkuv1.UploadRecordingRequest(nil), ts.msgs...), ts.opens, ts.closed
}

// eventually polls cond until it holds, for stream shutdowns that happen in
// a background goroutine.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func newTestKey(t *testing.T) (pubkeyB64, fingerprint string) {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub[:]), Fingerprint(pub[:])
}

// TestUploaderNoKeyUploadsNothing verifies the mandatory-encryption
// guarantee: without a workspace key the uploader never opens a stream and
// never sends a chunk, the recording stays local.
func TestUploaderNoKeyUploadsNothing(t *testing.T) {
	ts := newTestServer(t)
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
		KeyProvider: func() (string, string) {
			return "", ""
		},
	})

	if n, err := u.Write([]byte("plaintext must never leave the daemon")); err != nil || n == 0 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	msgs, opens, _ := ts.snapshot()
	if opens != 0 {
		t.Fatalf("upload stream opened %d times without a key, want 0", opens)
	}
	if len(msgs) != 0 {
		t.Fatalf("received %d messages without a key, want 0", len(msgs))
	}
}

// TestUploaderSealsChunks verifies that with a key every chunk is sealed:
// the stream opens with the right fingerprint and chunks are NaCl boxes,
// never raw data.
func TestUploaderSealsChunks(t *testing.T) {
	pubkeyB64, fp := newTestKey(t)
	ts := newTestServer(t)
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
		KeyProvider: func() (string, string) {
			return pubkeyB64, fp
		},
	})

	data := []byte("terminal output")
	if _, err := u.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}

	msgs, opens, closed := ts.snapshot()
	if opens != 1 {
		t.Fatalf("upload stream opened %d times, want 1", opens)
	}
	if closed != 1 {
		t.Fatalf("streams closed %d, want 1", closed)
	}
	if len(msgs) != 3 {
		t.Fatalf("received %d messages, want meta + chunk + final", len(msgs))
	}
	meta := msgs[0].GetMeta()
	if meta == nil || meta.GetKeyFingerprint() != fp {
		t.Fatalf("meta fingerprint = %q, want %q", meta.GetKeyFingerprint(), fp)
	}
	chunk := msgs[1].GetChunk()
	if len(chunk) != 4+32+24+box.Overhead+len(data) {
		t.Fatalf(
			"chunk length = %d, want %d (length prefix + ephemeral pub + nonce + box + data)",
			len(chunk),
			4+32+24+box.Overhead+len(data),
		)
	}
	if msgs[2].GetFinal() == nil {
		t.Fatalf("final message missing, got %v", msgs[2])
	}
}

// TestUploaderKeyClearedStopsUploading verifies that when the workspace key
// disappears mid-session the running stream is closed and nothing else is
// uploaded, so plaintext never reaches the backend.
func TestUploaderKeyClearedStopsUploading(t *testing.T) {
	pubkeyB64, fp := newTestKey(t)
	ts := newTestServer(t)
	state := pubkeyB64
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
		KeyProvider: func() (string, string) {
			if state == "" {
				return "", ""
			}
			return state, fp
		},
	})

	if _, err := u.Write([]byte("sealed data")); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		_, opens, _ := ts.snapshot()
		return opens == 1
	})

	state = ""
	if _, err := u.Write([]byte("more data")); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}

	// The old stream is closed in the background, wait for it.
	eventually(t, func() bool {
		_, _, closed := ts.snapshot()
		return closed == 1
	})

	msgs, opens, _ := ts.snapshot()
	if opens != 1 {
		t.Fatalf("upload stream opened %d times after key clear, want 1", opens)
	}
	var chunks [][]byte
	for _, m := range msgs {
		if m.GetChunk() != nil {
			chunks = append(chunks, m.GetChunk())
		}
	}
	if len(chunks) != 1 {
		t.Fatalf("received %d chunks, want one sealed chunk, no plaintext", len(chunks))
	}
	if len(chunks[0]) != 4+32+24+box.Overhead+len("sealed data") {
		t.Fatalf("chunk length = %d, want a sealed box of 11 bytes", len(chunks[0]))
	}
}
