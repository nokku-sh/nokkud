// Package client implements the daemon's connection to the Nokku backend.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/cenkalti/backoff/v7"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/mon/dpopclient"
	"github.com/nokku-sh/mon/tpm"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	nokkuv1connect "github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sshd"
	"github.com/nokku-sh/nokkud/internal/state"
)

const (
	dialTimeout   = 30 * time.Second
	enrollTimeout = 30 * time.Second
	syncTimeout   = 15 * time.Second
	// retryUploadsEvery is how often recordings the backend missed are
	// uploaded again.
	retryUploadsEvery = 5 * time.Minute
)

// signerSalt namespaces the daemon's DPoP key. Salt registry: mon/README.md.
const signerSalt = "nokku-daemon"

var errDaemonRejected = errors.New("daemon rejected by backend")

type Options struct {
	Insecure    bool
	RequireTPM  bool
	EnrollToken string
}

type Client struct {
	cache  *state.Cache
	config *state.Config
	dpop   *dpopclient.Client

	// Set by Run before any goroutine starts.
	srv     *sshd.Server
	sshAddr netip.AddrPort
	relays  sync.WaitGroup

	cc  nokkuv1connect.CertificateServiceClient
	rc  nokkuv1connect.RecordingServiceClient
	dc  nokkuv1connect.DaemonServiceClient
	dcs nokkuv1connect.DaemonControlServiceClient
	dss nokkuv1connect.DaemonSessionServiceClient
}

// New builds the backend clients and enrolls when opts carries a token.
func New(ctx context.Context, cache *state.Cache, config *state.Config, opts Options) (*Client, error) {
	httpc, err := dpopclient.NewHTTPClient(opts.Insecure, dialTimeout)
	if err != nil {
		return nil, err
	}
	// The identity is bound to the enrollment, so only a new enrollment may
	// replace a changed one. It registers the new key anyway.
	onChange := tpm.FailOnIdentityChange
	if opts.EnrollToken != "" {
		onChange = tpm.RecreateIdentity
	}
	proofer, err := dpopclient.NewProofer(
		[]byte(signerSalt),
		paths.SignerStateFile(),
		opts.RequireTPM,
		onChange,
	)
	if err != nil {
		return nil, err
	}

	c := &Client{cache: cache, config: config}
	apiURL := config.APIURL
	c.dpop = dpopclient.New(proofer, httpc, func() string { return config.SessionToken }, dpopclient.Options{
		BaseURL:           apiURL,
		UnboundProcedures: map[string]bool{nokkuv1connect.DaemonServiceEnrollDaemonProcedure: true},
		UserAgent:         buildinfo.UserAgent("nokkud"),
	})
	interceptors := connect.WithInterceptors(c.dpop)
	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, apiURL, interceptors)
	c.rc = nokkuv1connect.NewRecordingServiceClient(httpc, apiURL, interceptors)
	c.dc = nokkuv1connect.NewDaemonServiceClient(httpc, apiURL, interceptors)
	c.dcs = nokkuv1connect.NewDaemonControlServiceClient(httpc, apiURL, interceptors)
	c.dss = nokkuv1connect.NewDaemonSessionServiceClient(httpc, apiURL, interceptors)

	if opts.EnrollToken != "" {
		if err = c.enroll(ctx, opts.EnrollToken); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// enroll trades the token for a daemon session. The DPoP proof is unbound,
// the server binds the issued session to the daemon's key.
func (c *Client) enroll(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()
	res, err := c.dc.EnrollDaemon(ctx, &nokkuv1.EnrollDaemonRequest{Token: &token})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if res.GetWorkspaceId() == "" || res.GetTargetId() == "" || res.GetId() == "" || res.GetAccessToken() == "" {
		return errors.New("enroll: backend returned an incomplete enrollment")
	}
	// A re-enrollment may move the host to another workspace, so nothing the
	// old one trusted may survive until the first sync.
	c.cache.Clear()
	for _, f := range []string{paths.UserCAFile(), paths.RetiredCAFile(), paths.HostKeyCert()} {
		if err = os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("enroll: drop previous trust: %w", err)
		}
	}
	c.config.WorkspaceID = res.GetWorkspaceId()
	c.config.TargetID = res.GetTargetId()
	c.config.DaemonID = res.GetId()
	c.config.SessionToken = res.GetAccessToken()
	c.cache.SetDaemonConfig(res.GetConfig())
	if err = c.config.Save(); err != nil {
		return err
	}
	return c.cache.Save()
}

// RecordingSink streams one session recording to the backend.
func (c *Client) RecordingSink(ctx context.Context, sessionID, username string) io.WriteCloser {
	return recording.NewUploader(ctx, c.rc, sessionID, username)
}

// retryUploads uploads recordings whose live upload never completed, such as
// sessions recorded while the backend was down.
func (c *Client) retryUploads(ctx context.Context) {
	t := time.NewTicker(retryUploadsEvery)
	defer t.Stop()
	for {
		if err := recording.UploadPending(ctx, c.rc); err != nil {
			slog.Debug("recording upload retry failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Run syncs, keeps the host cert fresh, and holds the control stream open
// until ctx is done or the backend rejects the daemon. sshAddr is where srv
// listens.
func (c *Client) Run(ctx context.Context, srv *sshd.Server, sshAddr netip.AddrPort) error {
	c.srv = srv
	c.sshAddr = sshAddr
	// Deferred in this order so relays are canceled before they are joined.
	defer c.relays.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := c.syncDaemon(ctx)
	if errors.Is(err, errDaemonRejected) {
		return err
	}
	if err != nil {
		slog.Warn("initial sync failed, serving from cache", "error", err)
	}
	go c.watchCertificates(ctx)
	go c.retryUploads(ctx)

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	b.MaxInterval = time.Minute
	warned := false
	for {
		start := time.Now()
		err = c.runControlStream(ctx)
		if errors.Is(err, errDaemonRejected) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		// A rejected stream may carry a fresh DPoP nonce for the next dial.
		c.dpop.LearnFromError(err)

		// Connect returns before the backend answers, so only a stream that
		// stayed up proves the backend was reachable.
		if time.Since(start) > 2*heartbeatInterval {
			b.Reset()
			warned = false
		}
		next := b.NextBackOff()
		if !warned {
			slog.Warn("control stream down, retrying in background", "error", err)
			warned = true
		} else {
			slog.Debug("control stream retry failed", "error", err, "retry_in", next.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(next):
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
