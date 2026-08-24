package recording

import (
	"context"
	"log/slog"
	"sync"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// Uploader is an [io.WriteCloser] that streams a recording's compressed
// chunks to the backend on one UploadRecording stream. The backend encrypts
// the stream at rest with its own key, so the daemon sends plaintext over the
// authenticated channel and never seals or holds a recording key.
//
// The caller keeps writing after an upload failure. The uploader drops the
// chunk but never errors the caller, because the local file must keep the
// data either way. The backend marks the recording truncated when the stream
// ends without a final message.
type Uploader struct {
	ctx    context.Context
	client nokkuv1connect.RecordingServiceClient

	sessionID string
	username  string

	mu     sync.Mutex
	stream *connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse]
	failed bool
	closed bool
}

// UploaderOptions configures an Uploader.
type UploaderOptions struct {
	SessionID string
	Username  string
}

// NewUploader builds an Uploader. The stream opens lazily on the first write,
// so an unreachable backend never fails the session.
func NewUploader(
	ctx context.Context,
	client nokkuv1connect.RecordingServiceClient,
	opts UploaderOptions,
) *Uploader {
	return &Uploader{
		ctx:       ctx,
		client:    client,
		sessionID: opts.SessionID,
		username:  opts.Username,
	}
}

// Write sends one batch. It always reports success so the local recording
// never fails because of the backend.
func (u *Uploader) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed || u.failed {
		return len(p), nil
	}

	if u.stream == nil {
		if err := u.openLocked(); err != nil {
			u.failLocked("open upload stream", err)
			return len(p), nil
		}
	}

	if err := u.stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: p},
	}); err != nil {
		u.failLocked("send recording chunk", err)
		return len(p), nil
	}
	return len(p), nil
}

// Close finalizes the recording and closes the upload stream. Safe to call
// after a failure, the stream is still closed and the error logged.
func (u *Uploader) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	if u.stream == nil {
		return nil
	}
	_ = u.stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	})
	resp, err := u.stream.CloseAndReceive()
	if err != nil {
		slog.Debug("recording upload closed", "session_id", u.sessionID, "error", err)
		return nil
	}
	slog.Debug(
		"recording uploaded",
		"session_id", u.sessionID,
		"size", resp.GetSizeBytes(),
	)
	return nil
}

// openLocked opens the stream and sends the metadata message. Caller holds u.mu.
func (u *Uploader) openLocked() error {
	stream, err := u.client.UploadRecording(u.ctx)
	if err != nil {
		return err
	}
	if sendErr := stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Meta{
			Meta: &nokkuv1.RecordingMeta{
				RecordingId: &u.sessionID,
				Username:    &u.username,
			},
		},
	}); sendErr != nil {
		return sendErr
	}
	u.stream = stream
	return nil
}

// failLocked records the failure. The stream is left open for Close to shut
// down, the backend marks the recording truncated. Caller holds u.mu.
func (u *Uploader) failLocked(where string, err error) {
	u.failed = true
	slog.Warn(
		"recording upload failed, keeping local copy",
		"session_id", u.sessionID,
		"where", where,
		"error", err,
	)
}
