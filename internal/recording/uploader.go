package recording

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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
	err    error // why the upload failed, nil while it is healthy
	closed bool
	done   chan struct{}
	cancel context.CancelFunc
	close  func() error
}

// NewUploader builds an Uploader and starts its sender goroutine.
func NewUploader(
	ctx context.Context,
	client nokkuv1connect.RecordingServiceClient,
	sessionID, username string,
) *Uploader {
	ctx, cancel := context.WithCancel(ctx)
	u := &Uploader{
		client:    client,
		sessionID: sessionID,
		username:  username,
		chunks:    make(chan []byte, maxBufferedChunks),
		done:      make(chan struct{}),
		cancel:    cancel,
	}
	u.close = sync.OnceValue(u.finish)
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

	if u.closed || u.err != nil {
		return len(p), nil
	}

	select {
	case u.chunks <- append([]byte(nil), p...):
	default:
		// Dropping middle chunks would corrupt the rest of the gzip stream,
		// so the whole upload is abandoned instead.
		u.failLocked("upload queue full", errors.New("queue full"))
	}
	return len(p), nil
}

// Close finalizes the upload and reports whether the backend has all of it.
// Safe to call after a failure or twice. The wait for the backend is bounded
// by uploadCloseTimeout.
func (u *Uploader) Close() error { return u.close() }

func (u *Uploader) finish() error {
	u.mu.Lock()
	u.closed = true
	u.mu.Unlock()

	close(u.chunks)

	// Wait for the sender to drain the queue and finalize the stream, so a
	// session that exits immediately is not cut off mid-upload.
	var err error
	select {
	case <-u.done:
	case <-time.After(uploadCloseTimeout):
		err = errors.New("upload timed out")
	}
	// Abort a send that outlived the drain window so the sender goroutine
	// cannot hang forever on a stalled stream.
	u.cancel()
	u.mu.Lock()
	defer u.mu.Unlock()
	return cmp.Or(u.err, err)
}

// sendLoop sends queued chunks until Close drains the queue, then finalizes
// the stream. After a failure chunks are discarded so writers never block.
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
	// Best-effort final message: a failed send surfaces through CloseAndReceive.
	_ = stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	})
	if _, err := stream.CloseAndReceive(); err != nil {
		u.fail("finish upload", err)
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

// fail records the failure. The stream is left open, the backend marks the
// recording truncated.
func (u *Uploader) fail(where string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.failLocked(where, err)
}

func (u *Uploader) failLocked(where string, err error) {
	if u.err != nil {
		return
	}
	u.err = fmt.Errorf("%s: %w", where, err)
	slog.Warn(
		"recording upload failed, keeping local copy",
		"session_id", u.sessionID,
		"where", where,
		"error", err,
	)
}
