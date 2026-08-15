package recording

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"connectrpc.com/connect"
	"golang.org/x/crypto/nacl/box"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// Uploader is an [io.WriteCloser] that seals recording chunks with the
// workspace key and streams them to the backend on one UploadRecording
// stream. Every chunk uses a fresh ephemeral keypair and nonce, so each
// opens independently with the owner's private key. Without a key nothing
// is uploaded and the recording stays local.
//
// The caller keeps writing after an upload failure. The uploader drops the
// chunk but never errors the caller, because the local file must keep the
// data either way. The backend marks the recording truncated when the
// stream ends without a final message.
type Uploader struct {
	ctx    context.Context
	client nokkuv1connect.RecordingServiceClient

	// keyProvider returns the current workspace key (base64) and its
	// fingerprint, re-read per chunk. A rotation picked up by a sync
	// restarts the stream with the new key, a cleared key stops the upload.
	keyProvider func() (pubkeyB64, fingerprint string)

	sessionID string
	username  string

	mu       sync.Mutex
	stream   *connect.ClientStreamForClientSimple[nokkuv1.UploadRecordingRequest, nokkuv1.UploadRecordingResponse]
	streamFP string // fingerprint the open stream was sealed with
	seq      int
	failed   bool
	closed   bool
}

// UploaderOptions configures an Uploader.
type UploaderOptions struct {
	SessionID string
	Username  string
	// KeyProvider returns the current recording public key (base64) and its
	// fingerprint, or ("", "") when no key is configured so nothing uploads.
	KeyProvider func() (pubkeyB64, fingerprint string)
}

// NewUploader builds an Uploader. The stream opens lazily on the first
// write, so an unreachable backend never fails the session.
func NewUploader(
	ctx context.Context,
	client nokkuv1connect.RecordingServiceClient,
	opts UploaderOptions,
) *Uploader {
	return &Uploader{
		ctx:         ctx,
		client:      client,
		keyProvider: opts.KeyProvider,
		sessionID:   opts.SessionID,
		username:    opts.Username,
	}
}

// Write seals one batch and sends it. It always reports success so the
// local recording never fails because of the backend. Without a workspace
// key nothing uploads.
func (u *Uploader) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.closed || u.failed {
		return len(p), nil
	}

	pubkeyB64, fp := u.currentKey()
	if pubkeyB64 == "" {
		u.stopLocked("no recording key configured, keeping local copy")
		return len(p), nil
	}

	// Key rotation mid-session restarts the stream with the new key. The
	// backend wiped the old chunks at key-set, so this stream continues
	// under the same recording id.
	if fp != u.streamFP {
		u.rotateLocked(fp)
	}
	if u.stream == nil {
		if err := u.openLocked(); err != nil {
			u.failLocked("open upload stream", err)
			return len(p), nil
		}
	}

	sealed, err := sealChunk(p, pubkeyB64)
	if err != nil {
		u.failLocked("seal recording chunk", err)
		return len(p), nil
	}

	if err = u.stream.Send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: sealed},
	}); err != nil {
		u.failLocked("send recording chunk", err)
		return len(p), nil
	}
	u.seq++
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
				RecordingId:    &u.sessionID,
				Username:       &u.username,
				KeyFingerprint: &u.streamFP,
			},
		},
	}); sendErr != nil {
		return sendErr
	}
	u.stream = stream
	return nil
}

// rotateLocked restarts the stream under a new key fingerprint. The old
// stream is closed in the background, its chunks were wiped at key-set.
// Caller holds u.mu. The first open of a session is not a rotation, it is
// logged at debug level.
func (u *Uploader) rotateLocked(fp string) {
	old := u.stream
	u.stream = nil
	u.streamFP = fp
	u.failed = false
	u.seq = 0
	if old != nil {
		go func() { _, _ = old.CloseAndReceive() }()
		slog.Info(
			"recording key rotated, restarting upload",
			"session_id", u.sessionID,
			"fingerprint", fp,
		)
	} else {
		slog.Debug(
			"recording upload started",
			"session_id", u.sessionID,
			"fingerprint", fp,
		)
	}
	if err := u.openLocked(); err != nil {
		u.failLocked("reopen upload stream", err)
	}
}

// stopLocked stops an ongoing upload when the workspace key disappeared.
// Plaintext must never be uploaded, so the recording stays local from here
// on. The old stream is closed in the background. Caller holds u.mu.
func (u *Uploader) stopLocked(reason string) {
	if u.stream == nil {
		return
	}
	old := u.stream
	u.stream = nil
	u.streamFP = ""
	u.failed = false
	u.seq = 0
	go func() { _, _ = old.CloseAndReceive() }()
	slog.Info(reason, "session_id", u.sessionID)
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

// currentKey returns the current workspace recording key and fingerprint.
func (u *Uploader) currentKey() (string, string) {
	if u.keyProvider == nil {
		return "", ""
	}
	return u.keyProvider()
}

// sealChunk seals one chunk to the workspace key with a fresh ephemeral
// keypair. The output is [len(4 BE) || ephemeralPub(32) || nonce(24) ||
// ciphertext], the length prefix lets the browser walk the concatenated
// stream the backend stores.
func sealChunk(data []byte, pubkeyB64 string) ([]byte, error) {
	pub, err := ParsePublicKey(pubkeyB64)
	if err != nil {
		return nil, err
	}

	ephemeralPub, ephemeralPriv, genErr := box.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", genErr)
	}

	var nonce [24]byte
	if _, nonceErr := rand.Read(nonce[:]); nonceErr != nil {
		return nil, fmt.Errorf("generate nonce: %w", nonceErr)
	}

	var recipient [32]byte
	copy(recipient[:], pub)

	var sealed []byte
	sealed = box.Seal(sealed, data, &nonce, &recipient, ephemeralPriv)

	out := make([]byte, 0, 4+32+24+len(sealed))
	chunkLen := 32 + 24 + len(sealed)
	if chunkLen > math.MaxUint32 {
		return nil, fmt.Errorf("recording chunk too large: %d bytes", chunkLen)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(chunkLen))
	out = append(out, ephemeralPub[:]...)
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}
