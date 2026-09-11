// Package client implements the daemon's connection to the Nokku backend.
package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/mon/dpopclient"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	nokkuv1connect "github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
)

const (
	dialTimeout = 30 * time.Second
)

var errDaemonRejected = errors.New("daemon rejected by backend")

// Options carries the daemon's runtime configuration from main into the client.
type Options struct {
	Insecure    bool
	RequireTPM  bool
	EnrollToken string
	CAID        string
}

type Client struct {
	sessionSlots chan struct{}
	sessionWG    sync.WaitGroup

	sshSrv *sshd.Server
	cache  *state.Cache
	config *state.Config
	dpop   *dpopclient.Client

	cc  nokkuv1connect.CertificateServiceClient
	rc  nokkuv1connect.RecordingServiceClient
	dc  nokkuv1connect.DaemonServiceClient
	dcs nokkuv1connect.DaemonControlServiceClient
	dss nokkuv1connect.DaemonSessionServiceClient
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

func New(
	ctx context.Context,
	cache *state.Cache,
	config *state.Config,
	opts Options,
	sshSrv *sshd.Server,
) (*Client, error) {
	c := &Client{
		cache:        cache,
		config:       config,
		sshSrv:       sshSrv,
		sessionSlots: make(chan struct{}, maxConcurrentSessions),
	}

	if err := c.setupClients(opts.Insecure, opts.RequireTPM); err != nil {
		return nil, err
	}

	// The embedded SSH server records sessions through the same upload path as web sessions.
	if sshSrv != nil {
		sshSrv.SetRecordingSinkFactory(
			func(ctx context.Context, sessionID, username string) io.WriteCloser {
				if c.config.DaemonID == "" {
					return nopWriteCloser{}
				}
				return recording.NewUploader(ctx, c.rc, recording.UploaderOptions{
					SessionID: sessionID,
					Username:  username,
				})
			},
		)
	}

	if err := c.enroll(ctx, opts.EnrollToken, opts.CAID); err != nil {
		return nil, err
	}

	return c, nil
}

// setupClients builds the shared HTTP client and the connect service clients.
func (c *Client) setupClients(insecure, requireTPM bool) error {
	httpc, err := dpopclient.NewHTTPClient(insecure, dialTimeout)
	if err != nil {
		return err
	}

	proofer, perr := newProofer(requireTPM)
	if perr != nil {
		return perr
	}

	apiURL := c.config.APIURL
	c.dpop = dpopclient.New(
		proofer,
		httpc,
		func() string { return c.config.SessionToken },
		dpopclient.Options{
			BaseURL: apiURL,
			UnboundProcedures: map[string]bool{
				nokkuv1connect.DaemonServiceEnrollDaemonProcedure: true,
			},
			UserAgent: buildinfo.UserAgent("nokkud"),
		},
	)

	opts := connect.WithInterceptors(c.dpop)
	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, apiURL, opts)
	c.rc = nokkuv1connect.NewRecordingServiceClient(httpc, apiURL, opts)
	c.dc = nokkuv1connect.NewDaemonServiceClient(httpc, apiURL, opts)
	c.dcs = nokkuv1connect.NewDaemonControlServiceClient(httpc, apiURL, opts)
	c.dss = nokkuv1connect.NewDaemonSessionServiceClient(httpc, apiURL, opts)
	return nil
}

// Run keeps the control stream to the backend open until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	// Drain in-flight relay sessions on graceful shutdown.
	defer func() {
		if ctx.Err() != nil {
			c.sessionWG.Wait()
		}
	}()

	if c.config.DaemonID == "" {
		slog.Info("daemon not enrolled")
		return nil
	}

	if err := c.syncAll(ctx); err != nil {
		slog.Debug("initial sync failed", "error", err)
	}
	c.startWatchers(ctx)

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	b.MaxInterval = time.Minute

	var connected, warned, announced bool

	for {
		err := c.runControlStream(ctx, func() {
			b.Reset()
			connected = true
			warned = false
			if !announced {
				announced = true
				slog.Info("control stream connected")
			}
		})

		// A rejected stream may carry a fresh DPoP nonce: learn it before
		// dialing again so the reconnect signs with a current one.
		if err != nil && c.dpop != nil {
			c.dpop.LearnFromError(err)
		}

		if errors.Is(err, errDaemonRejected) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		next := b.NextBackOff()

		// Warn once per outage, then debug each retry so a long outage does
		// not spam the log.
		switch {
		case connected:
			connected = false
			slog.Warn("control stream disconnected, reconnecting in background", "error", err)
			warned = true
		case !warned:
			slog.Warn("cannot connect to backend, retrying in background", "error", err)
			warned = true
		default:
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
