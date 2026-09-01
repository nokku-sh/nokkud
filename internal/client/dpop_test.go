package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nokku-sh/nokkud/internal/dpop"

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
