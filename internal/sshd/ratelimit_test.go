package sshd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestServerConnRate verifies the per-IP connection rate limiter drops
// connections beyond the configured burst.
func TestServerConnRate(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{
		Tunables: Tunables{ConnRate: 1, ConnRateBurst: 2},
	})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	for i := range 2 {
		client, err := dial(t, addr, currentUser(t), auth)
		must.NoError(err, "dial %d within burst", i)
		_ = client.Close()
	}

	// The burst is spent: the next connection is dropped before the
	// handshake and the client sees a dead connection.
	_, err := dial(t, addr, currentUser(t), auth)
	is.Error(err, "dial beyond burst succeeded")
}

// TestServerConnRateDisabled verifies a zero ConnRate allows unlimited
// connection attempts.
func TestServerConnRateDisabled(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{})
	defer closeFn()

	auth := userCert(t, ca, testPrincipal)
	for i := range 5 {
		client, err := dial(t, addr, currentUser(t), auth)
		must.NoError(err, "dial %d with rate limiting disabled", i)
		_ = client.Close()
	}
}

// TestServerBanner verifies the pre-auth banner reflects the live tunables
// and can be turned off.
func TestServerBanner(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)

	dialWithBanner := func(opts Options) string {
		t.Helper()
		addr, closeFn := startTestServerOpts(t, ca, opts)
		defer closeFn()

		var got string
		cfg := &ssh.ClientConfig{
			User:            currentUser(t),
			Auth:            []ssh.AuthMethod{userCert(t, ca, testPrincipal)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 - test server
			Timeout:         10 * time.Second,
			BannerCallback: func(message string) error {
				got = message
				return nil
			},
		}
		client, err := ssh.Dial("tcp", addr, cfg)
		must.NoError(err, "dial")
		_ = client.Close()
		return got
	}

	banner := dialWithBanner(Options{Tunables: Tunables{Banner: true, Record: true}})
	is.Contains(banner, "recorded", "banner must mention recording when enabled")

	banner = dialWithBanner(Options{Tunables: Tunables{Banner: true}})
	is.NotContains(banner, "recorded", "banner must not mention recording when disabled")

	banner = dialWithBanner(Options{Tunables: Tunables{Banner: false, Record: true}})
	is.Empty(banner, "banner must be empty when disabled")
}
