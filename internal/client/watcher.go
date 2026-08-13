package client

import (
	"context"
	"log/slog"
	"time"
)

const (
	defaultDelay = 30 * time.Second
)

func (c *Client) startWatchers(ctx context.Context) {
	go c.watchCertificates(ctx)
}

// watchCertificates renews host certificates from their local expiry deadlines.
func (c *Client) watchCertificates(ctx context.Context) {
	delay := max(time.Until(c.ssh.NextRenewal(c.config.TargetID)), defaultDelay)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := c.renewHostCerts(ctx, false); err != nil {
				slog.Warn("certificate renewal", "error", err)
			}

			// Reschedule from the post-renewal certificate state.
			delay = max(time.Until(c.ssh.NextRenewal(c.config.TargetID)), defaultDelay)
			timer.Reset(delay)
		}
	}
}
