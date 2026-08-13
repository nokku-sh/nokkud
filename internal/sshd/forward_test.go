package sshd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// testEchoServer runs a TCP server that echoes any data it receives.
func testEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
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
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowForwarding: true})
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	if err != nil {
		t.Fatalf("forward dial: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want %q", buf, "ping")
	}
}

// TestServerDirectTCPIPDisabled verifies forwarding is rejected when off.
func TestServerDirectTCPIPDisabled(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	echo := testEchoServer(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, err = client.Dial("tcp", "127.0.0.1:"+portStr); err == nil {
		t.Fatal("forwarding unexpectedly allowed")
	}
}

// TestServerRemoteForward verifies -R style forwarding: a listener is bound on
// the server and connections are delivered to the client.
func TestServerRemoteForward(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowForwarding: true})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
	}
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
	if err != nil {
		t.Fatalf("dial server-side forward: %v", err)
	}
	defer sconn.Close()

	if _, err = sconn.Write([]byte("pong")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(sconn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("echo = %q, want %q", buf, "pong")
	}
}

// TestServerMaxSessions verifies the per-connection session cap.
func TestServerMaxSessions(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{MaxSessions: 2})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	s1, err := client.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	defer s1.Close()
	s2, err := client.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}
	defer s2.Close()

	if _, err = client.NewSession(); err == nil {
		t.Fatal("third session unexpectedly allowed")
	} else if !strings.Contains(err.Error(), "too many sessions") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Closing one session frees a slot (the server notices asynchronously).
	if err = s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}
	var s3 *ssh.Session
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s3, err = client.NewSession()
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("session after close: %v", err)
	}
	defer s3.Close()
}

// TestServerRemoteForwardLocalhost verifies a -R forward requested on the
// hostname "localhost" works: clients key their forward by the requested
// address, so the server must report it back verbatim even though the listener
// itself is pinned to loopback.
func TestServerRemoteForwardLocalhost(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowForwarding: true})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	ln, err := client.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
	}
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
	if err != nil {
		t.Fatalf("dial server-side forward: %v", err)
	}
	defer sconn.Close()

	if _, err = sconn.Write([]byte("pong")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(sconn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("echo = %q, want %q", buf, "pong")
	}
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

	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowForwarding: true})
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("dial server-side forward: %v\n%s", err, slurp(stderr))
	}
	defer sconn.Close()

	if _, err = sconn.Write([]byte("interop")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 7)
	if _, err = io.ReadFull(sconn, buf); err != nil {
		t.Fatalf("read: %v\n%s", err, slurp(stderr))
	}
	if string(buf) != "interop" {
		t.Fatalf("echo = %q, want %q", buf, "interop")
	}
}

func slurp(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}

// TestRemoteBindAddr verifies remote forwards are pinned to loopback unless
// gateway ports are enabled, matching OpenSSH's GatewayPorts=no default.
func TestRemoteBindAddr(t *testing.T) {
	cases := []struct {
		requested string
		gateway   bool
		want      string
	}{
		{"", false, "127.0.0.1"},
		{"0.0.0.0", false, "127.0.0.1"},
		{"192.168.1.5", false, "127.0.0.1"},
		{"", true, "0.0.0.0"},
		{"192.168.1.5", true, "192.168.1.5"},
	}
	for _, tc := range cases {
		if got := remoteBindAddr(tc.requested, tc.gateway); got != tc.want {
			t.Errorf("remoteBindAddr(%q, %v) = %q, want %q", tc.requested, tc.gateway, got, tc.want)
		}
	}
}

// TestServerGatewayPortsToggle verifies the runtime option flips the remote
// forward bind policy.
func TestServerGatewayPortsToggle(t *testing.T) {
	ca := newTestCA(t)
	srv, err := New(Options{
		Paths:           paths.Paths{ConfigDir: t.TempDir()},
		Principals:      func(string) ([]string, bool) { return nil, false },
		TrustedCAs:      []ssh.PublicKey{ca.pub},
		AllowForwarding: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if srv.gatewayPorts.Load() {
		t.Fatal("gateway ports enabled by default")
	}
	srv.SetOptions(Options{AllowForwarding: true, GatewayPorts: true})
	if !srv.gatewayPorts.Load() {
		t.Fatal("SetOptions did not enable gateway ports")
	}
}

func TestServerForwardingLargeTransfer(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowForwarding: true})
	defer closeFn()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 512*1024) // 8 MiB
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:"+portStr)
	if err != nil {
		t.Fatalf("forward dial: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	// The server side discards. Give it a moment, then confirm no error.
	time.Sleep(200 * time.Millisecond)
}
