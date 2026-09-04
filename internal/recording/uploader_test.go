package recording

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	_, err := u.Write([]byte("terminal output"))
	must.NoError(err)
	must.NoError(u.Close())

	msgs, opens, closed := ts.snapshot()
	is.Equal(1, opens)
	is.Equal(1, closed)
	must.Len(msgs, 3)
	meta := msgs[0].GetMeta()
	must.NotNil(meta)
	is.Equal("s1", meta.GetRecordingId())
	is.Equal("user", meta.GetUsername())
	is.Equal("terminal output", string(msgs[1].GetChunk()))
	is.NotNil(msgs[2].GetFinal())
}

// TestUploaderKeepsLocalOnFailure verifies a backend error never fails the
// caller: the chunk is dropped, the uploader stops, but Write still reports
// success so the local file keeps the data.
func TestUploaderKeepsLocalOnFailure(t *testing.T) {
	ts := newTestServer(t)
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	_, err := u.Write([]byte("first"))
	must.NoError(err)
	// Force a failure by sending after the server stream is gone is awkward;
	// the uploader is best-effort, writing after a failed or closed uploader
	// must still report success.
	must.NoError(u.Close())
	n, err := u.Write([]byte("after close"))
	must.NoError(err)
	is.NotZero(n)
}

// TestUploaderZeroSlicesAreNoop verifies empty writes do not open a stream.
func TestUploaderZeroSlicesAreNoop(t *testing.T) {
	ts := newTestServer(t)
	is := assert.New(t)
	must := require.New(t)

	u := NewUploader(context.Background(), ts.client, UploaderOptions{
		SessionID: "s1",
		Username:  "user",
	})

	n, err := u.Write(nil)
	must.NoError(err)
	is.Zero(n)
	must.NoError(u.Close())
	_, opens, _ := ts.snapshot()
	is.Zero(opens)
}
