// Package client implements the daemon's connection to the Nokku
// backend: enrollment, sync, host certificates and the control stream,
// all authenticated with signed challenges rather than bearer tokens.
package client

import (
	"context"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v7"
	"github.com/urfave/cli/v3"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

// Client is the daemon's backend-facing state: signer, config and
// principal cache, plus the certificate/daemon/control-stream RPC clients.
type Client struct {
	sessionSlots chan struct{}
	paths        paths.Paths

	ssh    *hostcerts.Manager
	cache  *state.Cache
	config *state.Config
	signer tpm.Signer

	// sshReload is called after a host certificate sync so the embedded SSH
	// server can adopt renewed certs / rotated CAs without a restart.
	sshReload func() error

	// sshApplyConfig is called after a daemon sync so the embedded SSH server
	// can pick up runtime options (e.g. session recording) live.
	sshApplyConfig func(record bool)

	cc  nokkuv1connect.CertificateServiceClient
	dc  nokkuv1connect.DaemonServiceClient
	dcs nokkuv1connect.DaemonControlServiceClient
	dss nokkuv1connect.DaemonSessionServiceClient
}

// New builds a Client sharing the caller's principal cache, so backend
// updates reach the embedded SSH server immediately. config is the
// caller-loaded enrollment state, already merged with flag values.
func New(
	ctx context.Context,
	cmd *cli.Command,
	p paths.Paths,
	cache *state.Cache,
	config *state.Config,
) (*Client, error) {
	// The signing identity is created before enrollment so the enrollment
	// request can register its public key. It is also required by the
	// request interceptor for post-enrollment authentication.
	signer, err := tpm.New(p, cmd.Bool("require-tpm"))
	if err != nil {
		return nil, err
	}

	c := &Client{
		cache:        cache,
		config:       config,
		signer:       signer,
		ssh:          hostcerts.New(p),
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

// SetSSHReload registers a callback invoked after host certificate syncs so
// the embedded SSH server can hot-reload renewed certs and CAs.
func (c *Client) SetSSHReload(fn func() error) {
	c.sshReload = fn
}

// SetSSHApplyConfig registers a callback invoked after daemon syncs so the
// embedded SSH server can apply runtime options (like recording) live.
func (c *Client) SetSSHApplyConfig(fn func(record bool)) {
	c.sshApplyConfig = fn
}

// Run keeps the control stream to the backend open until ctx is
// cancelled. No-op before enrollment.
func (c *Client) Run(ctx context.Context) {
	if c.config.DaemonID == "" {
		slog.Info("daemon not enrolled")
		return
	}

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

		if ctx.Err() != nil {
			return
		}

		// Reconnect on every disconnect, including a clean close: a backend
		// deploy or drain closing the stream must not take the whole daemon
		// down. A long-lived stream resets the backoff so a routine drop
		// reconnects promptly.
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
			return
		case <-timer.C:
		}

		if err = c.syncAll(ctx); err != nil {
			slog.Debug("sync after reconnect", "error", err)
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
