package client

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

const (
	enrollTimeout = 30 * time.Second
)

func (c *Client) enroll(ctx context.Context, token, caid string) error {
	if token == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()

	// Register the signing identity with the backend so it can verify the
	// daemon's request challenges after enrollment.
	pub, err := c.signer.Public()
	if err != nil {
		return fmt.Errorf("failed to read signing key: %w", err)
	}
	method := c.signer.Method()
	pubkey := string(pub)

	res, err := c.dc.EnrollDaemon(ctx, &nokkuv1.EnrollDaemonRequest{
		Token:      &token,
		CaId:       &caid,
		AuthMethod: &method,
		AuthPubkey: &pubkey,
	})
	if err != nil {
		if connect.CodeOf(err) == connect.CodeAlreadyExists {
			return nil // ignore, already enrolled
		}
		return fmt.Errorf("failed to enroll: %w", err)
	}

	c.config.WorkspaceID = res.GetWorkspaceId()
	c.config.TargetID = res.GetTargetId()
	c.config.DaemonID = res.GetId()
	c.cache.SetDaemonConfig(res.GetConfig())

	if c.config.WorkspaceID == "" {
		return fmt.Errorf("failed to enroll: empty workspace ID")
	}
	if c.config.TargetID == "" {
		return fmt.Errorf("failed to enroll: empty target ID")
	}
	if c.config.DaemonID == "" {
		return fmt.Errorf("failed to enroll: empty daemon ID")
	}
	if err = c.config.Save(); err != nil {
		return err
	}
	return c.cache.Save()
}
