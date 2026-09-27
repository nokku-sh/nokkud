package client

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

// syncDaemon pulls principals, config and CA from the backend and applies
// them. A failed sync leaves the cache as it was, so auth keeps working.
func (c *Client) syncDaemon(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	res, err := c.dc.SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{
		PrivateIps: c.sshEndpoints(),
		Users:      sysutil.SystemUsers(),
		Metadata:   sysutil.Metadata(),
	})
	if err != nil {
		return err
	}

	switch res.GetStatus() {
	case nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED:
		// Drop the enrollment on disk only. The in-memory config is read
		// concurrently and the process exits right after.
		c.cache.Clear()
		if err = c.cache.Save(); err != nil {
			slog.Error("persist cleared cache on rejection", "error", err)
		}
		if err = (&state.Config{APIURL: c.config.APIURL}).Save(); err != nil {
			slog.Error("persist cleared config on rejection", "error", err)
		}
		return errDaemonRejected
	case nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
	case nokkuv1.DaemonStatus_DAEMON_STATUS_UNSPECIFIED, nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING:
		return nil
	}

	// Re-sign under a new CA before taking the new state. If that fails the
	// cached version stays stale and the next heartbeat retries the sync.
	if ca := res.GetCaPublicKey(); ca != "" && !caMatches(ca) {
		if err = c.renewHostCerts(ctx, true); err != nil {
			return fmt.Errorf("renew host cert after CA rollover: %w", err)
		}
	}

	principals := make(map[string][]string, len(res.GetPrincipals()))
	for _, p := range res.GetPrincipals() {
		principals[p.GetUsername()] = p.GetIds()
	}
	c.cache.Replace(principals, res.GetConfig(), res.GetStateVersion())
	c.srv.SetPolicy(sshd.PolicyFrom(res.GetConfig()))
	return c.cache.Save()
}

// caMatches reports whether the CA file on disk already holds key.
func caMatches(key string) bool {
	data, err := os.ReadFile(paths.UserCAFile())
	return err == nil && bytes.Equal(bytes.TrimSpace(data), []byte(strings.TrimSpace(key)))
}

func (c *Client) renewHostCerts(ctx context.Context, force bool) error {
	renewed, err := hostcerts.RenewHostCerts(ctx, c.config.TargetID, c.signHostCert, force)
	if err != nil || !renewed {
		return err
	}
	if err = c.srv.Reload(); err != nil {
		slog.Warn("reload embedded ssh server", "error", err)
	}
	return nil
}

func (c *Client) signHostCert(ctx context.Context, pub []byte) (*nokkuv1.SignSSHCertificateResponse, error) {
	return c.cc.SignSSHCertificate(ctx, &nokkuv1.SignSSHCertificateRequest{
		WorkspaceId: &c.config.WorkspaceID,
		PublicKey:   new(string(pub)),
		Type:        nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_HOST.Enum(),
	})
}

// sshEndpoints pairs each private IP with the SSH port, so the backend knows
// how to reach this daemon directly.
func (c *Client) sshEndpoints() []string {
	port := strconv.Itoa(int(c.sshAddr.Port()))
	var endpoints []string
	for _, ip := range sysutil.PrivateIPs() {
		endpoints = append(endpoints, net.JoinHostPort(ip, port))
	}
	return endpoints
}
