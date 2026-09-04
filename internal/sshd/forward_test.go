package sshd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// testEchoServer runs a TCP server that echoes any data it receives.
func testEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "echo listen")
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

// TestServerDirectTCPIP verifies -L style forwarding: a direct-tcpip channel
// reaches the requested destination.
func TestServerDirectTCPIP(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{AllowForwarding: true}})
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	must.NoError(err, "forward dial")
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	must.NoError(err, "write")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	must.NoError(err, "read")
	is.Equal("ping", string(buf))
}

// TestServerDirectTCPIPDisabled verifies forwarding is rejected when off.
func TestServerDirectTCPIPDisabled(t *testing.T) {
	is := assert.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	require.NoError(t, err, "dial")
	defer client.Close()

	_, err = client.Dial("tcp", "127.0.0.1:"+portStr)
	is.Error(err, "forwarding unexpectedly allowed")
}

// TestServerRemoteForward verifies -R style forwarding: a listener is bound on
// the server and connections are delivered to the client.
func TestServerRemoteForward(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{AllowForwarding: true}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "remote listen")
	defer ln.Close()

	// The client's listener accepts the forwarded-tcpip channel opened for
	// each inbound server-side connection, echoing the data.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	// Connect to the server-side listener as a plain TCP client.
	sconn, err := net.Dial("tcp", ln.Addr().String())
	must.NoError(err, "dial server-side forward")
	defer sconn.Close()

	_, err = sconn.Write([]byte("pong"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(sconn, buf)
	must.NoError(err, "read")
	is.Equal("pong", string(buf))
}

// TestServerMaxSessions verifies the per-connection session cap.
func TestServerMaxSessions(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{MaxSessions: 2}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	s1, err := client.NewSession()
	must.NoError(err, "session 1")
	defer s1.Close()
	s2, err := client.NewSession()
	must.NoError(err, "session 2")
	defer s2.Close()

	_, err = client.NewSession()
	must.ErrorContains(err, "too many sessions")

	// Closing one session frees a slot (the server notices asynchronously).
	must.NoError(s1.Close(), "close s1")
	var s3 *ssh.Session
	is.Eventually(func() bool {
		s3, err = client.NewSession()
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	must.NoError(err, "session after close")
	defer s3.Close()
}

// TestServerRemoteForwardLocalhost verifies a -R forward requested on the
// hostname "localhost" works: clients key their forward by the requested
// address, so the server must report it back verbatim even though the listener
// itself is pinned to loopback.
func TestServerRemoteForwardLocalhost(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{AllowForwarding: true}})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	ln, err := client.Listen("tcp", "localhost:0")
	must.NoError(err, "remote listen")
	defer ln.Close()

	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	sconn, err := net.Dial("tcp", ln.Addr().String())
	must.NoError(err, "dial server-side forward")
	defer sconn.Close()

	_, err = sconn.Write([]byte("pong"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(sconn, buf)
	must.NoError(err, "read")
	is.Equal("pong", string(buf))
}

// TestServerRemoteForwardInterop drives ssh -R with the real OpenSSH client:
// the server binds a listener and delivers inbound connections to the client's
// end of the forward.
func TestServerRemoteForwardInterop(t *testing.T) {
	if !isTestBinary() {
		t.Skip("requires the test binary on PATH")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}

	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{AllowForwarding: true}})
	defer closeFn()
	host, port := hostPort(t, addr)

	// Echo server: what the client's forwarded end talks to.
	echo := testEchoServer(t)
	defer echo.Close()
	_, echoPortStr, _ := net.SplitHostPort(echo.Addr().String())

	// A TCP listener that represents the -R bound port on the server side.
	// The remote forward is bound via a placeholder port. OpenSSH -R binds on
	// the server to the requested port. Use a free port.
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err)
	_, boundPortStr, _ := net.SplitHostPort(bound.Addr().String())
	_ = bound.Close()

	user := currentUser(t)
	identity := userCertFile(t, ca)

	// ssh -R <boundPort>:<echoHost>:<echoPort> -N
	cmd := exec.Command(
		sshBin,
		"-p", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-R", fmt.Sprintf("%s:127.0.0.1:%s", boundPortStr, echoPortStr),
		"-N",
		fmt.Sprintf("%s@%s", user, host),
	)
	stderr, err := cmd.StderrPipe()
	must.NoError(err)
	must.NoError(cmd.Start(), "start ssh")
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// Give the forward a moment to be established.
	time.Sleep(500 * time.Millisecond)

	// Connect to the server-side bound port. Traffic should be delivered to
	// the client's -R end and echoed.
	sconn, err := net.Dial("tcp", "127.0.0.1:"+boundPortStr)
	if err != nil {
		must.NoError(err, "dial server-side forward\n%s", slurpAfterKill(cmd, stderr))
	}
	defer sconn.Close()

	_, err = sconn.Write([]byte("interop"))
	must.NoError(err, "write")
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 7)
	_, err = io.ReadFull(sconn, buf)
	if err != nil {
		must.NoError(err, "read\n%s", slurpAfterKill(cmd, stderr))
	}
	is.Equal("interop", string(buf))
}

// slurpAfterKill drains ssh's stderr for the failure message. ssh -N never
// exits on its own, so reading the pipe blocks forever unless the process is
// killed first.
func slurpAfterKill(cmd *exec.Cmd, stderr io.Reader) string {
	_ = cmd.Process.Kill()
	b, _ := io.ReadAll(stderr)
	_, _ = cmd.Process.Wait()
	return string(b)
}

// TestRemoteBindAddr verifies remote forwards are pinned to loopback unless
// gateway ports are enabled, matching OpenSSH's GatewayPorts=no default.
func TestRemoteBindAddr(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		gateway   bool
		want      string
	}{
		{"empty request pins loopback", "", false, "127.0.0.1"},
		{"wildcard request pins loopback", "0.0.0.0", false, "127.0.0.1"},
		{"lan request pins loopback", "192.168.1.5", false, "127.0.0.1"},
		{"empty request with gateway binds wildcard", "", true, "0.0.0.0"},
		{"lan request with gateway binds lan", "192.168.1.5", true, "192.168.1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			is.Equal(tt.want, remoteBindAddr(tt.requested, tt.gateway))
		})
	}
}

// TestServerGatewayPortsToggle verifies the runtime option flips the remote
// forward bind policy.
func TestServerGatewayPortsToggle(t *testing.T) {
	is := assert.New(t)
	must := require.New(t)
	ca := newTestCA(t)
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())
	srv, err := New(Options{
		Principals: func(string) []string { return nil },
		TrustedCAs: []ssh.PublicKey{ca.pub},
		Tunables:   Tunables{AllowForwarding: true},
	})
	must.NoError(err, "new server")
	is.False(srv.tun.Load().GatewayPorts, "gateway ports enabled by default")
	srv.SetTunables(Tunables{AllowForwarding: true, GatewayPorts: true})
	is.True(srv.tun.Load().GatewayPorts, "SetTunables did not enable gateway ports")
}

func TestServerForwardingLargeTransfer(t *testing.T) {
	must := require.New(t)
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{Tunables: Tunables{AllowForwarding: true}})
	defer closeFn()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 512*1024) // 8 MiB
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must.NoError(err, "listen")
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		if _, copyErr := io.Copy(io.Discard, c); copyErr != nil {
			t.Errorf("server read: %v", copyErr)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	must.NoError(err, "dial")
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	must.NoError(err, "forward dial")
	defer conn.Close()

	_, err = conn.Write(payload)
	must.NoError(err, "write")
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	// The server side discards. Give it a moment, then confirm no error.
	time.Sleep(200 * time.Millisecond)
}
