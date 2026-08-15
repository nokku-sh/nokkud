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
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/hostcerts"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

const syncTimeout = 15 * time.Second

func (c *Client) syncAll(ctx context.Context) error {
	if c.config.DaemonID == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	if err := c.syncDaemon(ctx); err != nil {
		return err
	}
	if err := c.renewHostCerts(ctx, false); err != nil {
		return err
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

	switch res.GetStatus() {
	case nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED:
		// The backend revoked this daemon: clear the enrollment and stop.
		c.config.Clear()
		if saveErr := c.config.Save(); saveErr != nil {
			slog.Error("persist cleared config on rejection", "error", saveErr)
		}
		slog.Error("daemon rejected, exiting")
		return errDaemonRejected
	case nokkuv1.DaemonStatus_DAEMON_STATUS_ACCEPTED:
		// Apply below.
	case nokkuv1.DaemonStatus_DAEMON_STATUS_UNSPECIFIED,
		nokkuv1.DaemonStatus_DAEMON_STATUS_PENDING:
		return nil // Nothing to apply
	}

	c.config.SetDaemonConfig(res.GetConfig())

	if c.sshSrv != nil {
		c.sshSrv.SetRecord(res.GetConfig().GetRecordSessions())
	}

	c.cache.Clear()
	for _, p := range res.GetPrincipals() {
		c.cache.SetUUIDs(p.GetUsername(), p.GetIds())
	}

	// CA rollover, re-sign the host certificate under the new authority and
	// reload the server before acknowledging the new state.
	if ca := res.GetCaPublicKey(); ca != "" && !c.caMatches(ca) {
		if renewErr := c.renewHostCerts(ctx, true); renewErr != nil {
			return fmt.Errorf("renew host certificates after CA rollover: %w", renewErr)
		}
	}

	c.cache.SetStateVersion(res.GetStateVersion())
	if saveErr := c.cache.Save(); saveErr != nil {
		return saveErr
	}

	return nil
}

// caMatches reports whether the cached CA file already holds key.
func (c *Client) caMatches(key string) bool {
	data, err := os.ReadFile(c.paths.UserCAFile())
	if err != nil {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(data), []byte(strings.TrimSpace(key)))
}

func (c *Client) renewHostCerts(ctx context.Context, force bool) error {
	renewed, err := c.ssh.RenewHostCerts(ctx, c.config.TargetID, c.signHostCert, force)
	slog.Debug("renew host certificates", "renewed", renewed, "force", force, "error", err)
	if err != nil {
		return err
	}
	if renewed > 0 {
		c.reloadSSH()
	}
	return nil
}

func (c *Client) reloadSSH() {
	if c.sshSrv == nil {
		return
	}
	if err := c.sshSrv.Reload(); err != nil {
		slog.Warn("reload embedded ssh server", "error", err)
	}
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
	return c.cc.SignSSHCertificate(ctx, req)
}

// sshEndpoints combines each private IP with the SSH listen port, so the
// backend knows how to reach the daemon.
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

// sshPort extracts the TCP port from an SSH listen address.
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
