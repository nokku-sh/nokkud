package recording

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

const (
	maxBufferedChunks  = 64
	uploadCloseTimeout = 30 * time.Second
)

type Uploader struct {
	client    nokkuv1connect.RecordingServiceClient
	sessionID string
	username  string

	chunks chan []byte
	mu     sync.Mutex
	failed bool
	closed bool
	done   chan struct{}
}

type UploaderOptions struct {
	SessionID string
	Username  string
}

// NewUploader builds an Uploader and starts its sender goroutine.
func NewUploader(
	ctx context.Context,
	client nokkuv1connect.RecordingServiceClient,
	opts UploaderOptions,
) *Uploader {
	u := &Uploader{
		client:    client,
		sessionID: opts.SessionID,
		username:  opts.Username,
		chunks:    make(chan []byte, maxBufferedChunks),
		done:      make(chan struct{}),
	}
	go u.sendLoop(ctx)
	return u
}

// Write queues one batch for upload. It always reports success so the local
// recording never fails because of the backend.
func (u *Uploader) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed || u.failed {
		return len(p), nil
	}

	select {
	case u.chunks <- append([]byte(nil), p...):
	default:
		// Dropping middle chunks would corrupt the gzip stream for
		// everything after them, so the whole upload is abandoned
		// instead. The backend marks the recording truncated.
		u.failLocked("upload queue full", errors.New("queue full"))
	}
	return len(p), nil
}

// Close finalizes the upload. Safe to call after a failure or twice. The
// wait for the backend is bounded by uploadCloseTimeout; on timeout the
// stream is abandoned and the recording marked truncated server-side.
func (u *Uploader) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	u.mu.Unlock()

	close(u.chunks)

	// The sender drains the queue, sends the final message, and closes the
	// stream. Waiting here keeps a session that exits immediately from
	// being cut off mid-upload.
	select {
	case <-u.done:
	case <-time.After(uploadCloseTimeout):
		slog.Warn(
			"recording upload close timed out, the backend may mark the recording truncated",
			"session_id", u.sessionID,
			"timeout", uploadCloseTimeout,
		)
	}
	return nil
}

// sendLoop sends queued chunks until Close drains the queue, then finalizes
// the stream. Once the upload fails, remaining chunks are discarded so
// writers never block.
func (u *Uploader) sendLoop(ctx context.Context) {
	defer close(u.done)

	var stream *connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse]
	broken := false
	for chunk := range u.chunks {
		if broken {
			continue
		}
		if stream == nil {
			var err error
			stream, err = u.open(ctx)
			if err != nil {
				u.fail("open upload stream", err)
				broken = true
				continue
			}
		}
		if err := stream.Send(&nokkuv1.UploadRecordingRequest{
			Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: chunk},
		}); err != nil {
			u.fail("send recording chunk", err)
			broken = true
		}
	}

	if stream == nil || broken {
		return
	}
	// Best-effort final message: a failed send still surfaces through
	// CloseAndReceive's error.
	_ = stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	})
	if _, err := stream.CloseAndReceive(); err != nil {
		slog.Debug("recording upload closed", "session_id", u.sessionID, "error", err)
		return
	}
	slog.Debug("recording uploaded", "session_id", u.sessionID)
}

// open starts the upload stream and sends the metadata message.
func (u *Uploader) open(ctx context.Context) (
	*connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse],
	error,
) {
	stream, err := u.client.UploadRecording(ctx)
	if err != nil {
		return nil, err
	}
	if err = stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Meta{
			Meta: &nokkuv1.RecordingMeta{
				RecordingId: &u.sessionID,
				Username:    &u.username,
			},
		},
	}); err != nil {
		return nil, err
	}
	return stream, nil
}

// fail records the failure. The stream is left as is, the backend marks the
// recording truncated.
func (u *Uploader) fail(where string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.failLocked(where, err)
}

func (u *Uploader) failLocked(where string, err error) {
	u.failed = true
	slog.Warn(
		"recording upload failed, keeping local copy",
		"session_id", u.sessionID,
		"where", where,
		"error", err,
	)
}
