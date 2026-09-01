package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/nokku-sh/mon/dpop"

	nokkuv1connect "github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
	"github.com/nokku-sh/nokkud/internal/state"
)

func newTestProofer(t *testing.T) *dpop.Proofer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := dpop.NewProofer(key, dpop.ProoferOptions{})
	if err != nil {
		t.Fatalf("new proofer: %v", err)
	}
	return p
}

// proofClaims decodes the payload of a compact JWT without verifying it.
func proofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a compact JWT: %q", proof)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err = json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestDPoPAuthEnrolledUsesDPoPScheme(t *testing.T) {
	t.Parallel()
	st := &state.Config{SessionToken: "sess-token", APIURL: "https://app.example.com"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	if err := a.sign(header, "/nokku.v1.DaemonService/SyncDaemon"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := header.Get("Authorization"); got != "DPoP sess-token" {
		t.Errorf("Authorization = %q, want %q", got, "DPoP sess-token")
	}
	if header.Get("DPoP") == "" {
		t.Fatal("expected a DPoP proof header")
	}
	if _, ok := proofClaims(t, header.Get("DPoP"))["ath"]; !ok {
		t.Error("enrolled proof must carry an ath claim")
	}
}

func TestDPoPAuthEnrollUnboundProof(t *testing.T) {
	t.Parallel()
	st := &state.Config{APIURL: "https://app.example.com"} // no SessionToken yet
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	if err := a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty (no token on enroll)", got)
	}
	proof := header.Get("DPoP")
	if proof == "" {
		t.Fatal("expected a DPoP proof header")
	}
	if _, ok := proofClaims(t, proof)["ath"]; ok {
		t.Error("enrollment proof must not carry an ath claim")
	}
}

func TestDPoPAuthHTUHasNoDoubleSlash(t *testing.T) {
	t.Parallel()
	st := &state.Config{APIURL: "https://app.example.com"} // no SessionToken yet
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	if err := a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure); err != nil {
		t.Fatalf("sign: %v", err)
	}
	proof := header.Get("DPoP")
	if proof == "" {
		t.Fatal("expected a DPoP proof header")
	}
	if got := proofClaims(t, proof)["htu"]; got != "https://app.example.com"+nokkuv1connect.DaemonServiceEnrollDaemonProcedure {
		t.Errorf("proof htu = %v", got)
	}
}

func TestDPoPAuthNoTokenNoEnrollIsNoop(t *testing.T) {
	t.Parallel()
	st := &state.Config{APIURL: "https://app.example.com"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	header := http.Header{}
	if err := a.sign(header, "/nokku.v1.DaemonService/SyncDaemon"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty", got)
	}
	if header.Get("DPoP") != "" {
		t.Error("expected no DPoP proof for a non-enroll call without a token")
	}
}

func TestDPoPAuthHTUUsesCanonicalServerURL(t *testing.T) {
	t.Parallel()
	st := &state.Config{APIURL: "http://localhost:3000"} // connect address
	a := &dpopAuth{
		config:    st,
		proofer:   newTestProofer(t),
		serverURL: "https://app.example.com", // canonical URL advertised by the server
	}

	header := http.Header{}
	if err := a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure); err != nil {
		t.Fatalf("sign: %v", err)
	}
	want := "https://app.example.com" + nokkuv1connect.DaemonServiceEnrollDaemonProcedure
	if got := proofClaims(t, header.Get("DPoP"))["htu"]; got != want {
		t.Errorf("proof htu = %v, want %v", got, want)
	}
}

func TestDPoPAuthLearnNonceLearnsServerURL(t *testing.T) {
	t.Parallel()
	st := &state.Config{APIURL: "http://localhost:3000"}
	a := &dpopAuth{config: st, proofer: newTestProofer(t)}

	err := connect.NewError(connect.CodeUnauthenticated, errors.New("stale DPoP nonce"))
	err.Meta().Set("DPoP-Nonce", "nonce-2")
	err.Meta().Set(urlHeader, "https://app.example.com")
	if !a.LearnNonce(err) {
		t.Fatal("LearnNonce() = false, want true")
	}

	header := http.Header{}
	if err := a.sign(header, nokkuv1connect.DaemonServiceEnrollDaemonProcedure); err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims := proofClaims(t, header.Get("DPoP"))
	if got := claims["nonce"]; got != "nonce-2" {
		t.Errorf("proof nonce = %v, want nonce-2", got)
	}
	want := "https://app.example.com" + nokkuv1connect.DaemonServiceEnrollDaemonProcedure
	if got := claims["htu"]; got != want {
		t.Errorf("proof htu = %v, want %v", got, want)
	}
}
