package client

import (
	"context"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v7"

	"github.com/nokku-sh/nokkud/internal/hostcerts"
)

// minRenewDelay is the poll interval while no host cert exists yet.
const minRenewDelay = 30 * time.Second

// watchCertificates keeps the host certificate renewed.
func (c *Client) watchCertificates(ctx context.Context) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = minRenewDelay
	b.MaxInterval = 30 * time.Minute
	failing := false
	for {
		var delay time.Duration
		if err := c.renewHostCerts(ctx, false); err != nil {
			delay = b.NextBackOff()
			if !failing {
				slog.Warn("host cert renewal failed, retrying in background", "error", err)
			}
			failing = true
		} else {
			if failing {
				slog.Info("host cert renewed")
			}
			failing = false
			b.Reset()
			delay = max(time.Until(hostcerts.NextRenewal(c.config.TargetID)), minRenewDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
