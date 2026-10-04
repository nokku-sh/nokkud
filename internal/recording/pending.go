package recording

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// A recording keeps the plain suffix until the backend confirmed the whole
// upload, so everything else is still pending.
const (
	castSuffix     = ".cast.gz"
	uploadedSuffix = ".uploaded" + castSuffix
)

// active holds the paths of recordings still being written or live uploaded.
var active sync.Map

func markUploaded(path string) {
	done := strings.TrimSuffix(path, castSuffix) + uploadedSuffix
	if err := os.Rename(path, done); err != nil {
		slog.Warn("mark recording uploaded", "path", path, "error", err)
	}
}

// UploadPending uploads finished recordings the backend does not have yet,
// oldest first, such as sessions recorded while it was unreachable. It stops
// at the first failure, the next call retries.
func UploadPending(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient) error {
	// Filenames start with the timestamp, so Glob's order is oldest first.
	matches, err := filepath.Glob(filepath.Join(paths.RecordsDir(), "*"+castSuffix))
	if err != nil {
		return err
	}
	for _, path := range matches {
		if strings.HasSuffix(path, uploadedSuffix) {
			continue
		}
		if _, busy := active.Load(path); busy {
			continue
		}
		err = uploadFile(ctx, client, path)
		if connect.CodeOf(err) == connect.CodeInvalidArgument {
			// Already finalized, or a file the backend will never take.
			slog.Warn("recording not accepted by the backend, not retrying", "path", path, "error", err)
			err = nil
		}
		if err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(path), err)
		}
		markUploaded(path)
	}
	return nil
}

func uploadFile(ctx context.Context, client nokkuv1connect.DaemonControlServiceClient, path string) error {
	hdr, err := readHeader(path)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	f, err := os.Open(path) // #nosec G304 - a file from the recordings dir
	if err != nil {
		return err
	}
	defer f.Close()

	stream, err := client.UploadRecording(ctx)
	if err != nil {
		return err
	}
	send := func(req *nokkuv1.UploadRecordingRequest) error {
		if sendErr := stream.Send(req); sendErr != nil {
			_, recvErr := stream.CloseAndReceive()
			return errors.Join(sendErr, recvErr)
		}
		return nil
	}
	if err = send(&nokkuv1.UploadRecordingRequest{Msg: &nokkuv1.UploadRecordingRequest_Meta{
		Meta: &nokkuv1.RecordingMeta{RecordingId: &hdr.SessionID, Username: &hdr.User},
	}}); err != nil {
		return err
	}
	buf := make([]byte, 32<<10)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err = send(&nokkuv1.UploadRecordingRequest{
				Msg: &nokkuv1.UploadRecordingRequest_Chunk{Chunk: buf[:n]},
			}); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_, _ = stream.CloseAndReceive()
			return readErr
		}
	}
	if err = send(&nokkuv1.UploadRecordingRequest{
		Msg: &nokkuv1.UploadRecordingRequest_Final{Final: &nokkuv1.RecordingFinal{}},
	}); err != nil {
		return err
	}
	_, err = stream.CloseAndReceive()
	return err
}

// readHeader reads the asciicast header, the first line of the recording.
func readHeader(path string) (header, error) {
	var hdr header
	f, err := os.Open(path) // #nosec G304 - a file from the recordings dir
	if err != nil {
		return hdr, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return hdr, err
	}
	line, err := bufio.NewReader(gz).ReadBytes('\n')
	if err != nil {
		return hdr, fmt.Errorf("read recording header: %w", err)
	}
	if err = json.Unmarshal(line, &hdr); err != nil {
		return hdr, fmt.Errorf("parse recording header: %w", err)
	}
	if hdr.SessionID == "" {
		return hdr, errors.New("recording header has no session id")
	}
	return hdr, nil
}
