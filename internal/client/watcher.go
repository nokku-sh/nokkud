package client

import (
	"context"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v7"
)

const (
	defaultDelay = 30 * time.Second
)

func (c *Client) startWatchers(ctx context.Context) {
	go c.watchCertificates(ctx)
}

// watchCertificates keeps the host certificate renewed.
func (c *Client) watchCertificates(ctx context.Context) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = defaultDelay
	b.MaxInterval = 30 * time.Minute

	var retrying bool

	for {
		var delay time.Duration

		err := c.renewHostCerts(ctx, false)
		if err != nil {
			delay = b.NextBackOff()
			if !retrying {
				slog.Warn("certificate renewal failed, will retry in background", "error", err)
				retrying = true
			} else {
				slog.Debug(
					"certificate renewal retry failed",
					"error",
					err,
					"retry_in",
					delay.Round(time.Second),
				)
			}
		} else {
			if retrying {
				slog.Info("host certificate renewed successfully")
				retrying = false
			}
			b.Reset()
			// Sleep until the renewal deadline. Poll at a minimum
			// interval when no certificate exists yet.
			delay = max(time.Until(c.ssh.NextRenewal(c.config.TargetID)), defaultDelay)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
