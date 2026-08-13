// Package client implements the daemon's connection to the Nokku backend.
// Enrollment, sync, host certificates and the control stream, all
// authenticated with signed challenges rather than bearer tokens.
package client

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v7"
	"github.com/urfave/cli/v3"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

var errDaemonRejected = errors.New("daemon rejected by backend")

type Client struct {
	sessionSlots chan struct{}
	paths        paths.Paths

	ssh    *hostcerts.Manager
	sshSrv *sshd.Server
	cache  *state.Cache
	config *state.Config
	signer tpm.Signer

	cc  nokkuv1connect.CertificateServiceClient
	dc  nokkuv1connect.DaemonServiceClient
	dcs nokkuv1connect.DaemonControlServiceClient
	dss nokkuv1connect.DaemonSessionServiceClient
}

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

	c := &Client{
		cache:        cache,
		config:       config,
		signer:       signer,
		ssh:          hostcerts.New(p),
		sshSrv:       sshSrv,
		paths:        p,
		sessionSlots: make(chan struct{}, maxConcurrentSessions),
	}

	if err = c.setupClients(config.APIURL, cmd.Bool("insecure")); err != nil {
		return nil, err
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
// No-op before enrollment.
func (c *Client) Run(ctx context.Context) error {
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
	b.MaxInterval = 30 * time.Second

	for {
		start := time.Now()
		err := c.runControlStream(ctx)
		dwell := time.Since(start)

		if errors.Is(err, errDaemonRejected) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		// Reconnect on every disconnect, including a clean close
		if dwell >= 5*time.Second {
			b.Reset()
		}
		next := b.NextBackOff()
		if err != nil {
			slog.Warn("control stream disconnected, reconnecting", "error", err, "retry_in", next)
		} else {
			slog.Info("control stream closed, reconnecting", "retry_in", next)
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
