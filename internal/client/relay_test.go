package client

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

type fakeRelayStream struct {
	sent chan *nokkuv1.DaemonRelayRequest
	recv chan *nokkuv1.DaemonRelayResponse
}

func (s *fakeRelayStream) Send(req *nokkuv1.DaemonRelayRequest) error {
	s.sent <- req
	return nil
}

func (s *fakeRelayStream) Receive() (*nokkuv1.DaemonRelayResponse, error) {
	msg, ok := <-s.recv
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func TestLoopback(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	for addr, want := range map[string]string{
		"[::]:4022":         "127.0.0.1:4022",
		"0.0.0.0:4022":      "127.0.0.1:4022",
		"192.168.1.10:4022": "192.168.1.10:4022",
	} {
		is.Equal(want, loopback(netip.MustParseAddrPort(addr)), addr)
	}
}

func TestPumpRelayOut(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	stream := &fakeRelayStream{sent: make(chan *nokkuv1.DaemonRelayRequest, 16)}

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayOut(stream, conn) }()

	_, err := sshd.Write([]byte("SSH-2.0-OpenSSH\r\n"))
	require.NoError(t, err)

	req := <-stream.sent
	require.Equal(t, []byte("SSH-2.0-OpenSSH\r\n"), req.GetData())

	// sshd EOF ends the pump cleanly.
	require.NoError(t, sshd.Close())
	select {
	case pumpErr := <-errCh:
		require.NoError(t, pumpErr)
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not end on conn EOF")
	}
}

func TestPumpRelayOutConnClosed(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = sshd.Close() })

	stream := &fakeRelayStream{sent: make(chan *nokkuv1.DaemonRelayRequest, 16)}

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayOut(stream, conn) }()

	// Closing the read end unblocks the pump, the same way runRelay tears
	// down on stream end.
	require.NoError(t, conn.Close())
	select {
	case err := <-errCh:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not end on conn close")
	}
}

func TestPumpRelayIn(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	stream := &fakeRelayStream{recv: make(chan *nokkuv1.DaemonRelayResponse, 8)}

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayIn(stream, conn) }()

	stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Data{Data: []byte("banner line\n")},
	}
	buf := make([]byte, len("banner line\n"))
	_, err := io.ReadFull(sshd, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("banner line\n"), buf)

	// A closed frame ends the pump without touching conn.
	stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	}
	select {
	case pumpErr := <-errCh:
		require.NoError(t, pumpErr)
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not end on closed frame")
	}
}

func TestPumpRelayInReceiveError(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	stream := &fakeRelayStream{recv: make(chan *nokkuv1.DaemonRelayResponse)}
	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayIn(stream, conn) }()

	close(stream.recv)
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not end on receive error")
	}
}

func startStubSSHD(t *testing.T) (addr string, connCh <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			ch <- c
		}
	}()
	return ln.Addr().String(), ch
}

// TestRunRelayStreamRelaysBytes drives runRelayStream against a stub sshd
// listener: frames from the backend reach sshd, sshd bytes reach the
// backend, and a backend close tears the local side down.
func TestRunRelayStreamRelaysBytes(t *testing.T) {
	t.Parallel()
	baseline := runtime.NumGoroutine()
	addr, sshdCh := startStubSSHD(t)

	stream := &fakeRelayStream{
		sent: make(chan *nokkuv1.DaemonRelayRequest, 16),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 8),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- runRelayStream(t.Context(), stream, addr, "r1") }()

	ready := <-stream.sent
	require.NotNil(t, ready.GetReady())
	require.Equal(t, "r1", ready.GetReady().GetRelayId())

	sshd := <-sshdCh
	t.Cleanup(func() { _ = sshd.Close() })

	// Backend to sshd.
	stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Data{Data: []byte("hello sshd")},
	}
	buf := make([]byte, len("hello sshd"))
	_, err := io.ReadFull(sshd, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("hello sshd"), buf)

	// sshd to backend.
	_, err = sshd.Write([]byte("hello backend"))
	require.NoError(t, err)
	req := <-stream.sent
	require.Equal(t, []byte("hello backend"), req.GetData())

	// Backend closes: the relay answers with Closed and drops sshd.
	stream.recv <- &nokkuv1.DaemonRelayResponse{
		Msg: &nokkuv1.DaemonRelayResponse_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
	}
	select {
	case runErr := <-errCh:
		require.NoError(t, runErr)
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end on backend close")
	}
	closed := <-stream.sent
	require.NotNil(t, closed.GetClosed())
	_, err = sshd.Read(buf)
	require.Error(t, err, "sshd conn must be closed after backend close")

	// No relay goroutines outlive the run.
	is := assert.New(t)
	is.Eventually(func() bool {
		return runtime.NumGoroutine() <= baseline+2
	}, 2*time.Second, 10*time.Millisecond)
}

// TestRunRelayStreamSSHDExit covers the sshd side ending first: the backend
// gets a Closed frame and the run returns cleanly.
func TestRunRelayStreamSSHDExit(t *testing.T) {
	t.Parallel()
	addr, sshdCh := startStubSSHD(t)

	stream := &fakeRelayStream{
		sent: make(chan *nokkuv1.DaemonRelayRequest, 8),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 1),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- runRelayStream(t.Context(), stream, addr, "r2") }()

	ready := <-stream.sent
	require.NotNil(t, ready.GetReady())

	sshd := <-sshdCh
	require.NoError(t, sshd.Close())

	closed := <-stream.sent
	require.NotNil(t, closed.GetClosed())

	// Unblock the stream receive so teardown can join its pumps.
	close(stream.recv)
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end on sshd exit")
	}
}

// TestRunRelayStreamDialFailure covers the fast-fail path: Ready goes out
// first, a refused sshd dial yields Closed and a descriptive error.
func TestRunRelayStreamDialFailure(t *testing.T) {
	t.Parallel()
	stream := &fakeRelayStream{
		sent: make(chan *nokkuv1.DaemonRelayRequest, 8),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 1),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- runRelayStream(t.Context(), stream, "127.0.0.1:1", "r3") }()

	ready := <-stream.sent
	require.NotNil(t, ready.GetReady())

	closed := <-stream.sent
	require.NotNil(t, closed.GetClosed())

	select {
	case err := <-errCh:
		require.ErrorContains(t, err, "dial local sshd")
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not fail fast on dial failure")
	}
}
