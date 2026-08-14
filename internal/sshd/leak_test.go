package sshd

import (
	"runtime"
	"testing"
	"time"

	"github.com/nokku-sh/nokkud/internal/leaktest"
)

// Open and close session channels without sending shell/exec/subsystem,
// repeatedly, and verify the server still accepts fresh connections.
func TestSessionChannelNoCommandDoesNotLeak(t *testing.T) {
	// Registered first so it runs after closeFn: the profile must be read
	// with the server fully torn down. It is a no-op until the stdlib
	// goroutineleak profile is available (Go 1.27, or Go 1.26 with
	// GOEXPERIMENT=goroutineleakprofile).
	defer leaktest.VerifyNone(t)

	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	user := currentUser(t)

	baseline := runtime.NumGoroutine()

	for i := range 200 {
		client, err := dial(t, addr, user, auth)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		sess, err := client.NewSession()
		if err != nil {
			client.Close()
			t.Fatalf("new session %d: %v", i, err)
		}
		sess.Close()
		client.Close()
	}

	// Let the server-side connection teardown settle before counting.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+5 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if got := runtime.NumGoroutine(); got > baseline+5 {
		t.Fatalf("goroutines grew from %d to %d: leaked session goroutines", baseline, got)
	}

	client, err := dial(t, addr, user, auth)
	if err != nil {
		t.Fatalf("post-leak dial: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("post-leak new session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo ok")
	if err != nil {
		t.Fatalf("post-leak exec: %v", err)
	}
	if string(out) != "ok\n" {
		t.Fatalf("post-leak output = %q", out)
	}
}
