package recording

import (
	"context"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// NewSessionRecorder builds a recorder for one session. With a non-nil
// client, flushed batches are streamed to the backend for encryption at rest,
// otherwise the session is only recorded locally. Callers typically pass a
// context detached from the session's lifetime (context.WithoutCancel): the
// upload stream must survive session teardown so Close can drain the queue
// even after the session context is cancelled.
func NewSessionRecorder(
	ctx context.Context,
	client nokkuv1connect.RecordingServiceClient,
	opts Options,
) (*Recorder, error) {
	if client != nil {
		opts.Sink = NewUploader(ctx, client, UploaderOptions{
			SessionID: opts.SessionID,
			Username:  opts.Username,
		})
	}
	return New(opts)
}
