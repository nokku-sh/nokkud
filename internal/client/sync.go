package client

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

func (c *Client) syncAll(ctx context.Context) error {
	if c.config.DaemonID == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := c.syncDaemon(ctx); err != nil {
		return err
	}
	if err := c.syncCertificates(ctx); err != nil {
		return err
	}
	if c.sshReload != nil {
		if err := c.sshReload(); err != nil {
			slog.Warn("reload embedded ssh server", "error", err)
		}
	}
	return nil
}

func (c *Client) syncDaemon(ctx context.Context) error {
	res, err := c.dc.SyncDaemon(ctx, &nokkuv1.SyncDaemonRequest{
		PrivateIps: c.sshEndpoints(),
		Users:      sysutil.SystemUsers(),
		Metadata:   sysutil.Metadata(),
	})
	if err != nil {
		return err
	}
	c.config.DaemonConfig = res.GetConfig()

	if c.sshApplyConfig != nil {
		c.sshApplyConfig(res.GetConfig().GetRecordSessions())
	}

	c.cache.Clear()
	for _, p := range res.GetPrincipals() {
		c.cache.SetUUIDs(p.GetUsername(), p.GetIds())
	}
	return c.cache.Save()
}

func (c *Client) syncCertificates(ctx context.Context) error {
	_, err := c.ssh.RenewHostCerts(ctx, c.config.TargetID, c.signHostCert)
	slog.Debug("renew host certificates", "error", err)
	return err
}

// signHostCert requests a fresh host certificate for kp from the backend.
func (c *Client) signHostCert(
	ctx context.Context,
	kp hostcerts.KeyPair,
) (*nokkuv1.SignSSHCertificateResponse, error) {
	req := &nokkuv1.SignSSHCertificateRequest{
		WorkspaceId: &c.config.WorkspaceID,
		PublicKey:   new(string(kp.PublicKeyData)),
		Type:        nokkuv1.SignSSHCertificateRequest_CERTIFICATE_TYPE_HOST.Enum(),
	}
	if c.config.CAID != "" {
		req.CaId = &c.config.CAID
	}
	return c.cc.SignSSHCertificate(ctx, req)
}

// sshEndpoints combines each private IP with the SSH listen port, so the
// backend knows how to reach the daemon. Returns nil when the embedded SSH
// server is disabled or its address is unusable.
func (c *Client) sshEndpoints() []string {
	port := sshPort(c.config.SSHAddr)
	if port == "" {
		return nil
	}

	ips := sysutil.PrivateIPs()
	endpoints := make([]string, 0, len(ips))
	for _, ip := range ips {
		endpoints = append(endpoints, net.JoinHostPort(ip, port))
	}
	return endpoints
}

// sshPort extracts the TCP port from an SSH listen address. Both host:port
// (":4022", "0.0.0.0:4022") and bare-port ("4022") forms are accepted, the
// latter matching how [net.Listen] treats a plain port. An empty string is
// returned when the server is disabled or the port is out of range.
func sshPort(addr string) string {
	if addr == "" {
		return ""
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return validPort(port)
	}
	return validPort(addr)
}

func validPort(port string) string {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return ""
	}
	return port
}
