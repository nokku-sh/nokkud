package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

func newHTTPClient(insecure bool) (*http.Client, error) {
	proto := new(http.Protocols)
	proto.SetHTTP1(false)
	proto.SetHTTP2(true)
	proto.SetUnencryptedHTTP2(true)

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("expected *http.Transport")
	}
	t := base.Clone()
	t.Protocols = proto
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	t.TLSClientConfig.MinVersion = tls.VersionTLS13
	if insecure {
		t.TLSClientConfig.InsecureSkipVerify = true // #nosec G402
	}

	t.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return &http.Client{Transport: t}, nil
}

func (c *Client) setupClients(apiURL string, insecure bool) error {
	httpc, err := newHTTPClient(insecure)
	if err != nil {
		return fmt.Errorf("http client: %w", err)
	}
	c.httpc = httpc

	c.auth = WithAuth(c.proofer, &c.config.SessionToken, apiURL).(*authInterceptor)
	opts := connect.WithInterceptors(c.auth)
	c.cc = nokkuv1connect.NewCertificateServiceClient(httpc, apiURL, opts)
	c.dc = nokkuv1connect.NewDaemonServiceClient(httpc, apiURL, opts)
	c.dcs = nokkuv1connect.NewDaemonControlServiceClient(httpc, apiURL, opts)
	c.dss = nokkuv1connect.NewDaemonSessionServiceClient(httpc, apiURL, opts)
	c.rc = nokkuv1connect.NewRecordingServiceClient(httpc, apiURL, opts)
	return nil
}
