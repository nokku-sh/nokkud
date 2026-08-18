package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/mizuchilabs/kagi/dpop"

	"github.com/nokku-sh/nokkud/internal/gen/nokku/v1/nokkuv1connect"
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

func TestAuthInterceptorHTUHasNoDoubleSlash(t *testing.T) {
	t.Parallel()

	a := &authInterceptor{baseURL: "http://localhost:3000"}

	got := a.htu(nokkuv1connect.DaemonServiceEnrollDaemonProcedure)
	want := "http://localhost:3000/nokku.v1.DaemonService/EnrollDaemon"
	if got != want {
		t.Fatalf("htu = %q, want %q", got, want)
	}
}

func TestAuthInterceptorHTUTrimsTrailingSlash(t *testing.T) {
	t.Parallel()

	// withAuth trims the trailing slash from baseURL, so htu must not
	// reintroduce a double slash.
	proofer := newTestProofer(t)
	tok := ""
	a := withAuth(proofer, &tok, "http://localhost:3000/")

	got := a.htu(nokkuv1connect.DaemonServiceEnrollDaemonProcedure)
	want := "http://localhost:3000/nokku.v1.DaemonService/EnrollDaemon"
	if got != want {
		t.Fatalf("htu = %q, want %q", got, want)
	}
}
