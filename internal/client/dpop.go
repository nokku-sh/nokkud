package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/nokku-sh/nokkud/internal/dpop"
	nokkuv1connect "github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/state"
)

// dpopAuth authenticates the daemon's control-plane RPCs: it sends the
// persisted session token with the "DPoP" scheme and binds every request to
// the daemon's signing key with a DPoP proof. Before enrollment there is no
// token, so the EnrollDaemon request goes out as an unbound proof instead. It
// learns the server nonce from the DPoP-Nonce response header and retries once
// when the server reports a stale nonce (RFC 9449 section 8).
type dpopAuth struct {
	config  *state.Config
	proofer *dpop.Proofer

	mu    sync.Mutex
	nonce string
}

// WithDPoP builds the interactive-session interceptor. baseURL is the API
// origin used to reconstruct each request's htu, matching the server's
// BaseURL configuration.
func WithDPoP(
	st *state.Config,
	proofer *dpop.Proofer,
	initialNonce string,
) connect.Interceptor {
	return &dpopAuth{
		config:  st,
		proofer: proofer,
		nonce:   initialNonce,
	}
}

func (a *dpopAuth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := a.sign(req.Header(), req.Spec().Procedure); err != nil {
			return nil, err
		}

		resp, err := next(ctx, req)
		if err != nil && a.learnNonce(err) {
			// Wipe the old DPoP header before signing again
			req.Header().Del("DPoP")
			if err = a.sign(req.Header(), req.Spec().Procedure); err != nil {
				return nil, err
			}
			return next(ctx, req)
		}
		return resp, err
	}
}

func (a *dpopAuth) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		_ = a.sign(conn.RequestHeader(), spec.Procedure)
		return conn
	}
}

func (a *dpopAuth) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// sign sets the DPoP-bound token and DPoP proof on the request header.
//
// Before enrollment there is no session token, so the EnrollDaemon request is
// sent with an unbound proof (no Authorization header, no ath claim); every
// other request carries the token per RFC 9449 section 7.1.
func (a *dpopAuth) sign(header http.Header, procedure string) error {
	token := a.config.SessionToken
	htu := a.config.APIURL + procedure

	if token == "" {
		// No session token yet: only the enrollment request is sent, with an
		// unbound proof that binds the daemon's key to the request itself.
		if procedure != nokkuv1connect.DaemonServiceEnrollDaemonProcedure {
			return nil
		}
		proof, err := a.proofer.Sign(http.MethodPost, htu, "", a.currentNonce())
		if err != nil {
			return connect.NewError(
				connect.CodeInternal,
				fmt.Errorf("failed to sign DPoP proof: %w", err),
			)
		}
		header.Set("DPoP", proof)
		return nil
	}

	// RFC 9449: MUST use "DPoP" scheme for bound tokens
	header.Set("Authorization", "DPoP "+token)
	proof, err := a.proofer.Sign(http.MethodPost, htu, dpop.ATH(token), a.currentNonce())
	if err != nil {
		return connect.NewError(
			connect.CodeInternal,
			fmt.Errorf("failed to sign DPoP proof: %w", err),
		)
	}
	header.Set("DPoP", proof)
	return nil
}

// learnNonce records a fresh nonce from a stale-nonce error response and
// reports whether the server advertised one (so the caller retries).
func (a *dpopAuth) learnNonce(err error) bool {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || connect.CodeOf(err) != connect.CodeUnauthenticated {
		return false
	}
	if n := cerr.Meta().Get("DPoP-Nonce"); n != "" {
		a.mu.Lock()
		a.nonce = n
		a.mu.Unlock()
		return true
	}
	return false
}

func (a *dpopAuth) currentNonce() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonce
}

// FetchNonce bootstraps the DPoP nonce from the server before the first
// DPoP-protected request, avoiding a deliberate 401 round-trip.
func FetchNonce(httpc *http.Client, baseURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/auth/nonce",
		nil,
	)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("DPoP-Nonce"), nil
}
