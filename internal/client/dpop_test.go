package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"

	"github.com/nokku-sh/mon/dpop"

	nokkuv1connect "github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/state"
)

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	must := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(err, "generate key")
	p, err := dpop.NewProofer(key, dpop.ProoferOptions{})
	must.NoError(err, "new proofer")
	return p
}

// proofClaims decodes the payload of a compact JWT without verifying it.
func proofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	must := require.New(t)
	parts := strings.Split(proof, ".")
	must.Len(parts, 3, "proof is not a compact JWT: %q", proof)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	must.NoError(err, "decode payload")
	var claims map[string]any
	must.NoError(json.Unmarshal(payload, &claims), "unmarshal claims")
	return claims
}

func TestDPoPAuthEnrolledUsesDPoPScheme(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{SessionToken: "sess-token", APIURL: "https://app.example.com"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	must.NoError(a.sign(header, "/nokku.v1.DaemonService/SyncDaemon"), "sign")
	is.Equal("DPoP sess-token", header.Get("Authorization"))
	is.NotEmpty(header.Get("DPoP"), "expected a DPoP proof header")
	is.Contains(proofClaims(t, header.Get("DPoP")), "ath", "enrolled proof must carry an ath claim")
}

func TestDPoPAuthEnrollUnboundProof(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{APIURL: "https://app.example.com"} // no SessionToken yet
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	must.NoError(a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure), "sign")
	is.Empty(header.Get("Authorization"), "no token on enroll")
	proof := header.Get("DPoP")
	is.NotEmpty(proof, "expected a DPoP proof header")
	is.NotContains(proofClaims(t, proof), "ath", "enrollment proof must not carry an ath claim")
}

func TestDPoPAuthHTUHasNoDoubleSlash(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{APIURL: "https://app.example.com"} // no SessionToken yet
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	must.NoError(a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure), "sign")
	proof := header.Get("DPoP")
	is.NotEmpty(proof, "expected a DPoP proof header")
	is.Equal(
		"https://app.example.com"+nokkuv1connect.DaemonServiceEnrollDaemonProcedure,
		proofClaims(t, proof)["htu"],
	)
}

func TestDPoPAuthNoTokenNoEnrollIsNoop(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{APIURL: "https://app.example.com"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	must.NoError(a.sign(header, "/nokku.v1.DaemonService/SyncDaemon"), "sign")
	is.Empty(header.Get("Authorization"))
	is.Empty(header.Get("DPoP"), "expected no DPoP proof for a non-enroll call without a token")
}

func TestDPoPAuthHTUUsesCanonicalServerURL(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{APIURL: "http://localhost:3000"} // connect address
	a := &dpopAuth{
		config:    st,
		proofer:   newTestProofer(t),
		serverURL: "https://app.example.com", // canonical URL advertised by the server
	}

	header := http.Header{}
	must.NoError(a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure), "sign")
	want := "https://app.example.com" + nokkuv1connect.DaemonServiceEnrollDaemonProcedure
	is.Equal(want, proofClaims(t, header.Get("DPoP"))["htu"])
}

func TestDPoPAuthLearnNonceLearnsServerURL(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	st := &state.Config{APIURL: "http://localhost:3000"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale DPoP nonce"))
	err.Meta().Set("DPoP-Nonce", "nonce-2")
	err.Meta().Set(urlHeader, "https://app.example.com")
	is.True(a.LearnNonce(err), "LearnNonce() = false, want true")

	header := http.Header{}
	must.NoError(a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure), "sign")
	claims := proofClaims(t, header.Get("DPoP"))
	is.Equal("nonce-2", claims["nonce"])
	is.Equal("https://app.example.com"+nokkuv1connect.DaemonServiceEnrollDaemonProcedure, claims["htu"])
}

// TestDPoPAuthRefreshesStaleNonceForStreams verifies streaming requests
// re-fetch the nonce when the cached one is old enough to have rotated out
// of the server's two-bucket acceptance window, and skip the fetch while it
// is fresh.
func TestDPoPAuthRefreshesStaleNonceForStreams(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
		w.Header().Set(urlHeader, "https://canonical.example.com")
	}))
	t.Cleanup(srv.Close)

	st := &state.Config{SessionToken: "sess-token", APIURL: srv.URL}
	a := &dpopAuth{
		config:    st,
		proofer:   newTestProofer(t),
		httpc:     srv.Client(),
		nonce:     "stale-nonce",
		learnedAt: time.Now().Add(-2 * nonceRefreshAfter),
	}

	a.refreshNonce(context.Background())
	a.mu.Lock()
	got := a.nonce
	a.mu.Unlock()
	is.Equal("fresh-nonce", got)
	is.Equal(1, hits)

	a.refreshNonce(context.Background())
	is.Equal(1, hits, "nonce endpoint hit again while the cached nonce was fresh")
}

// TestDPoPAuthUnaryRefreshesStaleNonce verifies unary requests also prefetch
// a fresh nonce when the cached one is stale, so the request succeeds on the
// first attempt instead of burning the deliberate 401 round trip.
func TestDPoPAuthUnaryRefreshesStaleNonce(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
	}))
	t.Cleanup(srv.Close)

	st := &state.Config{SessionToken: "sess-token", APIURL: srv.URL}
	a := &dpopAuth{
		config:    st,
		proofer:   newTestProofer(t),
		httpc:     srv.Client(),
		nonce:     "stale-nonce",
		learnedAt: time.Now().Add(-2 * nonceRefreshAfter),
	}

	var proof string
	unary := a.WrapUnary(func(_ context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		proof = req.Header().Get("DPoP")
		return connect.NewResponse(&nokkuv1.GetVersionResponse{}), nil
	})
	resp, err := unary(context.Background(), connect.NewRequest(&nokkuv1.GetVersionRequest{}))
	must.NoError(err, "unary")
	is.NotNil(resp)
	is.Equal(1, hits)
	is.Equal("fresh-nonce", proofClaims(t, proof)["nonce"])
}
