package sshd

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/nokku-sh/nokkud/internal/leaktest"
)

// TestMain checks the goroutineleak profile once after every test has torn
// down, so a leak in any test fails the suite.
func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}

// Open and close session channels without sending shell/exec/subsystem,
// repeatedly, and verify the server still accepts fresh connections.
func TestSessionChannelNoCommandDoesNotLeak(t *testing.T) {
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
