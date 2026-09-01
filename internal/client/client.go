// Package client implements the daemon's connection to the Nokku backend.
// Enrollment, sync, host certificates and the control stream, all
// authenticated with a DPoP-bound session token.
package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v7"
	"github.com/urfave/cli/v3"

	"github.com/nokku-sh/nokkud/internal/dpop"
	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

var errDaemonRejected = errors.New("daemon rejected by backend")

type Client struct {
	ctx          context.Context
	sessionSlots chan struct{}
	sessionWG    sync.WaitGroup
	paths        paths.Paths

	sshSrv  *sshd.Server
	cache   *state.Cache
	config  *state.Config
	signer  tpm.Signer
	proofer *dpop.Proofer
	auth    *dpopAuth
	httpc   *http.Client

	cc  nokkuv1connect.CertificateServiceClient
	dc  nokkuv1connect.DaemonServiceClient
	dcs nokkuv1connect.DaemonControlServiceClient
	dss nokkuv1connect.DaemonSessionServiceClient
	rc  nokkuv1connect.RecordingServiceClient
}

// nopWriteCloser discards writes. It stands in for the recording sink so the
// SSH server never has to special-case an unenrolled daemon.
type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// New builds a Client sharing the caller's principal cache, so backend
// updates reach the embedded SSH server immediately.
func New(
	ctx context.Context,
	cmd *cli.Command,
	p paths.Paths,
	cache *state.Cache,
	config *state.Config,
	sshSrv *sshd.Server,
) (*Client, error) {
	signer, err := tpm.New(p, cmd.Bool("require-tpm"))
	if err != nil {
		return nil, err
	}
	proofer, err := dpop.NewProofer(signer.CryptoSigner(), dpop.ProoferOptions{})
	if err != nil {
		return nil, err
	}

	c := &Client{
		ctx:          ctx,
		cache:        cache,
		config:       config,
		signer:       signer,
		proofer:      proofer,
		sshSrv:       sshSrv,
		paths:        p,
		sessionSlots: make(chan struct{}, maxConcurrentSessions),
	}

	if err = c.setupClients(config.APIURL, cmd.Bool("insecure")); err != nil {
		return nil, err
	}

	// The embedded SSH server records sessions through the same upload
	// path as web sessions.
	if sshSrv != nil {
		sshSrv.SetRecordingSinkFactory(func(sessionID, username string) io.WriteCloser {
			if c.config.DaemonID == "" {
				return nopWriteCloser{}
			}
			return recording.NewUploader(c.ctx, c.rc, recording.UploaderOptions{
				SessionID: sessionID,
				Username:  username,
			})
		})
	}

	if err = c.enroll(
		ctx,
		cmd.String("enroll"),
		cmd.String("ca"),
	); err != nil {
		return nil, err
	}

	return c, nil
}

// Run keeps the control stream to the backend open until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	// Graceful shutdown drains in-flight PTY sessions
	defer func() {
		if ctx.Err() != nil {
			c.sessionWG.Wait()
		}
	}()

	if c.config.DaemonID == "" {
		slog.Info("daemon not enrolled")
		return nil
	}

	// Sync the initial state
	if err := c.syncAll(ctx); err != nil {
		slog.Debug("initial sync", "error", err)
	}
	c.startWatchers(ctx)

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	b.MaxInterval = time.Minute

	var connected, offlineReported bool
	var connectLogged, disconnectLogged bool

	for {
		err := c.runControlStream(ctx, func() {
			b.Reset()
			if !connectLogged {
				slog.Info("control stream connected")
				connectLogged = true
			}
			connected = true
		})

		// A rejected stream may carry a fresh DPoP nonce: learn it before
		// dialing again so the reconnect signs with a current one.
		if err != nil && c.auth != nil {
			c.auth.LearnNonce(err)
		}

		if errors.Is(err, errDaemonRejected) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		next := b.NextBackOff()

		switch {
		case connected:
			connected = false
			if disconnectLogged {
				slog.Debug("control stream disconnected, reconnecting", "error", err)
			} else {
				disconnectLogged = true
				if err != nil {
					slog.Warn(
						"control stream disconnected, reconnecting in background",
						"error",
						err,
					)
				} else {
					slog.Info("control stream closed, reconnecting in background")
				}
			}
		case !offlineReported:
			offlineReported = true
			slog.Warn("cannot connect to backend, will keep retrying in background", "error", err)
		case err != nil:
			slog.Debug(
				"control stream reconnect attempt failed",
				"error",
				err,
				"retry_in",
				next.Round(time.Millisecond),
			)
		}

		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// DeleteDaemon removes this daemon's registration from the backend.
func (c *Client) DeleteDaemon(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err := c.dc.DeleteDaemon(ctx, &nokkuv1.DeleteDaemonRequest{})
	return err
}
