package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokkud/internal/id"
	"github.com/nokku-sh/nokkud/internal/tpm"
)

type authInterceptor struct {
	signer      tpm.Signer
	daemonID    *string
	hostname    string
	fingerprint string
}

// WithAuth signs outgoing RPCs with the daemon key and adds identity
// headers. Pre-enrollment calls (no daemonID) go out unsigned.
func WithAuth(signer tpm.Signer, daemonID *string) connect.Interceptor {
	a := &authInterceptor{signer: signer, daemonID: daemonID}
	if name, err := os.Hostname(); err == nil {
		a.hostname = name
	}
	a.fingerprint = id.MachineID()
	return a
}

func (a *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.setHeader(ctx, req.Header(), req.Spec().Procedure)
		return next(ctx, req)
	}
}

func (a *authInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.setHeader(ctx, conn.RequestHeader(), spec.Procedure)
		return conn
	}
}

func (a *authInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

func (a *authInterceptor) setHeader(ctx context.Context, header http.Header, procedure string) {
	if a.daemonID != nil && *a.daemonID != "" && a.signer != nil {
		challenge, err := a.challenge(ctx, *a.daemonID, procedure)
		if err != nil {
			slog.Warn("sign request challenge", "error", err)
		} else {
			header.Set("Authorization", "Nokku "+challenge)
		}
	}
	if buildinfo.Version != "" {
		header.Set("Nokku-Daemon-Version", buildinfo.Version)
	}
	if buildinfo.Commit != "" {
		header.Set("Nokku-Daemon-Commit", buildinfo.Commit)
	}
	if buildinfo.Date != "" {
		header.Set("Nokku-Daemon-Builddate", buildinfo.Date)
	}
	if a.hostname != "" {
		header.Set("Nokku-Daemon-Hostname", a.hostname)
	}
	if a.fingerprint != "" {
		header.Set("Nokku-Daemon-Fingerprint", a.fingerprint)
	}
}

// challenge builds a signed request challenge of the form
//
//	<daemonID>:<unixSeconds>:<nonce>:<procedure>:<base64url(signature)>
//
// The signature covers everything up to and including the procedure. A
// captured challenge cannot be replayed against a different RPC, and the
// backend rejects challenges older than its freshness window.
func (a *authInterceptor) challenge(
	ctx context.Context,
	daemonID, procedure string,
) (string, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := fmt.Sprintf("%s:%s:%s:%s", daemonID, ts, hex.EncodeToString(nonce), procedure)
	sig, err := a.signer.Sign(ctx, []byte(payload))
	if err != nil {
		return "", err
	}
	return payload + ":" + base64.RawURLEncoding.EncodeToString(sig), nil
}
