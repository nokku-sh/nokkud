package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kagi/dpop"
	"github.com/mizuchilabs/kata/buildinfo"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
)

// authInterceptor signs outgoing RPCs with the daemon's DPoP proof and adds
// identity headers. Pre-enrollment calls (no session token) go out unsigned.
type authInterceptor struct {
	proofer   *dpop.Proofer
	token     *string
	baseURL   string
	userAgent string

	mu    sync.Mutex
	nonce string
}

// withAuth authenticates control-plane RPCs with the daemon's DPoP-bound
// session. token points at the persisted session token (empty before
// enrollment); baseURL is the API origin used to reconstruct the htu.
func withAuth(proofer *dpop.Proofer, token *string, baseURL string) *authInterceptor {
	return &authInterceptor{
		proofer:   proofer,
		token:     token,
		baseURL:   strings.TrimRight(baseURL, "/"),
		userAgent: buildinfo.UserAgent("nk"),
	}
}

func (a *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.sign(req.Header(), req.Spec().Procedure, http.MethodPost)
		resp, err := next(ctx, req)
		if err != nil && a.learnNonce(err) {
			a.sign(req.Header(), req.Spec().Procedure, http.MethodPost)
			return next(ctx, req)
		}
		return resp, err
	}
}

func (a *authInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.sign(conn.RequestHeader(), spec.Procedure, http.MethodPost)
		return conn
	}
}

func (a *authInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}

// sign sets the bearer token, DPoP proof, and identity headers. Before
// enrollment there is no session token, so the enrollment request is signed
// with an unbound proof (no ath claim); every other request needs a token.
func (a *authInterceptor) sign(header http.Header, procedure, method string) {
	if a.proofer != nil {
		if a.token != nil && *a.token != "" {
			header.Set("Authorization", "Bearer "+*a.token)
			if proof, err := a.proofer.Sign(
				method,
				a.htu(procedure),
				dpop.ATH(*a.token),
				a.currentNonce(),
			); err == nil {
				header.Set("DPoP", proof)
			}
		} else if procedure == nokkuv1connect.DaemonServiceEnrollDaemonProcedure {
			// Enrollment has no access token: the proof binds the daemon's key
			// to the enrollment request itself.
			if proof, err := a.proofer.Sign(
				method,
				a.htu(procedure),
				"",
				a.currentNonce(),
			); err == nil {
				header.Set("DPoP", proof)
			}
		}
	}
	header.Set("User-Agent", a.userAgent)
}

func (a *authInterceptor) htu(procedure string) string {
	// procedure is a fully-qualified RPC path ("/pkg.Service/Method"), so no
	// separator is needed after the base URL.
	return a.baseURL + procedure
}

// learnNonce records a fresh nonce from a stale-nonce error response.
func (a *authInterceptor) learnNonce(err error) bool {
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

func (a *authInterceptor) currentNonce() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonce
}

// setNonce records a server nonce, used to bootstrap before the first
// DPoP-protected request so it does not need a stale-nonce round-trip.
func (a *authInterceptor) setNonce(n string) {
	a.mu.Lock()
	a.nonce = n
	a.mu.Unlock()
}

// FetchNonce bootstraps the DPoP nonce from the server.
func FetchNonce(ctx context.Context, httpc *http.Client, baseURL string) (string, error) {
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
