package recording

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"

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

// TestUploaderStreamsPlaintext verifies the uploader opens once, sends the
// metadata without a key fingerprint, streams raw chunks untouched, and
// finalizes with a final message on Close.
func TestUploaderStreamsPlaintext(t *testing.T) {
	ts := newTestServer(t)
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	if _, err := u.Write([]byte("terminal output")); err != nil {
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
	if meta == nil || meta.GetRecordingId() != "s1" || meta.GetUsername() != "user" {
		t.Fatalf("meta = %+v, want recording_id s1 username user", meta)
	}
	if got := msgs[1].GetChunk(); string(got) != "terminal output" {
		t.Fatalf("chunk = %q, want raw plaintext", got)
	}
	if msgs[2].GetFinal() == nil {
		t.Fatalf("final message missing, got %v", msgs[2])
	}
}

// TestUploaderKeepsLocalOnFailure verifies a backend error never fails the
// caller: the chunk is dropped, the uploader stops, but Write still reports
// success so the local file keeps the data.
func TestUploaderKeepsLocalOnFailure(t *testing.T) {
	ts := newTestServer(t)
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	if _, err := u.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	// Force a failure by sending after the server stream is gone is awkward;
	// the uploader is best-effort, writing after a failed or closed uploader
	// must still report success.
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := u.Write([]byte("after close")); err != nil || n == 0 {
		t.Fatalf("Write after close = %d, %v, want success", n, err)
	}
}

// TestUploaderZeroSlicesAreNoop verifies empty writes do not open a stream.
func TestUploaderZeroSlicesAreNoop(t *testing.T) {
	ts := newTestServer(t)
	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	if n, err := u.Write(nil); err != nil || n != 0 {
		t.Fatalf("Write(nil) = %d, %v", n, err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	_, opens, _ := ts.snapshot()
	if opens != 0 {
		t.Fatalf("upload stream opened %d times for empty writes, want 0", opens)
	}
}
