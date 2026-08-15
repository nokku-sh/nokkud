package recording

import (
	"context"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// NewSessionRecorder builds a recorder for one session. With a non-nil
// client, flushed batches are sealed and uploaded to the backend when the
// workspace has a recording key, otherwise the session is only recorded
// locally.
func NewSessionRecorder(
	p paths.Paths,
	client nokkuv1connect.RecordingServiceClient,
	keyProvider func() (pubkeyB64, fingerprint string),
	opts Options,
) (*Recorder, error) {
	if client != nil {
		opts.Sink = NewUploader(context.Background(), client, UploaderOptions{
			SessionID:   opts.SessionID,
			Username:    opts.Username,
			KeyProvider: keyProvider,
		})
	}
	return New(p, opts)
}
