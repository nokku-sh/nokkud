package recording

import (
	"context"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// NewSessionRecorder builds a recorder for one session. With a non-nil
// client, flushed batches are streamed to the backend for encryption at rest,
// otherwise the session is only recorded locally. The upload stream is bound
// to ctx, so cancelling ctx (e.g. on daemon shutdown) discards an in-flight
// upload instead of blocking on it.
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
