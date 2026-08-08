package client

import (
	"context"
	"log/slog"
	"time"
)

const (
	defaultDelay = 30 * time.Second
	syncInterval = 12 * time.Hour
)

func (c *Client) startWatchers(ctx context.Context) {
	go c.watchCertificates(ctx)
	go c.watchSync(ctx)
}

// watchSync periodically re-runs the full sync as a safety net.
func (c *Client) watchSync(ctx context.Context) {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.syncAll(ctx); err != nil {
				slog.Debug("periodic sync", "error", err)
			}
		}
	}
}

func (c *Client) watchCertificates(ctx context.Context) {
	delay := max(time.Until(c.ssh.NextRenewal(c.config.TargetID)), defaultDelay)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := c.syncCertificates(ctx); err != nil {
				slog.Warn("certificate renewal", "error", err)
			}

			// Reschedule from the post-renewal certificate state.
			delay = max(time.Until(c.ssh.NextRenewal(c.config.TargetID)), defaultDelay)
			timer.Reset(delay)
		}
	}
}
