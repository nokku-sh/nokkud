package client

import (
	"context"
	"io"
	"net"
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

func TestRelayDialAddr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr    string
		want    string
		wantErr string
	}{
		{addr: ":4022", want: "127.0.0.1:4022"},
		{addr: "*:4022", want: "127.0.0.1:4022"},
		{addr: "0.0.0.0:4022", want: "127.0.0.1:4022"},
		{addr: "[::]:4022", want: "127.0.0.1:4022"},
		{addr: "127.0.0.1:4022", want: "127.0.0.1:4022"},
		{addr: "192.168.1.10:4022", want: "192.168.1.10:4022"},
		{addr: "4022", want: "127.0.0.1:4022"},
		{addr: "", wantErr: "not configured"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			is := assert.New(t)
			got, err := relayDialAddr(tt.addr)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			is.Equal(tt.want, got)
		})
	}
}

func TestPumpRelayOut(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	stream := &fakeRelayStream{sent: make(chan *nokkuv1.DaemonRelayRequest, 16)}
	gate := make(chan struct{}, 1)
	resetIdle := func() {}

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayOut(t.Context(), stream, conn, gate, resetIdle) }()

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
	gate := make(chan struct{}, 1)

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayOut(t.Context(), stream, conn, gate, func() {}) }()

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

func TestPumpRelayOutGateHeldCancel(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	// A held gate blocks the pump in its select so cancel is the only exit.
	gate := make(chan struct{}, 1)
	gate <- struct{}{}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- pumpRelayOut(ctx, &fakeRelayStream{sent: make(chan *nokkuv1.DaemonRelayRequest, 1)}, conn, gate, func() {})
	}()

	// The pump only reaches the gate select after traffic arrives.
	go func() {
		_, _ = sshd.Write([]byte("ping"))
	}()

	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not end while gate was held")
	}
}

func TestPumpRelayIn(t *testing.T) {
	t.Parallel()
	conn, sshd := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = sshd.Close() })

	stream := &fakeRelayStream{recv: make(chan *nokkuv1.DaemonRelayResponse, 8)}
	resetIdle := func() {}

	errCh := make(chan error, 1)
	go func() { errCh <- pumpRelayIn(stream, conn, resetIdle) }()

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
	go func() { errCh <- pumpRelayIn(stream, conn, func() {}) }()

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

// TestRunRelayStreamUnconfiguredSSHD fails closed when the ssh listen
// address was cleared instead of dialing a garbage target.
func TestRunRelayStreamUnconfiguredSSHD(t *testing.T) {
	t.Parallel()
	stream := &fakeRelayStream{
		sent: make(chan *nokkuv1.DaemonRelayRequest, 8),
		recv: make(chan *nokkuv1.DaemonRelayResponse, 1),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- runRelayStream(t.Context(), stream, "", "r4") }()

	ready := <-stream.sent
	require.NotNil(t, ready.GetReady())
	closed := <-stream.sent
	require.NotNil(t, closed.GetClosed())

	select {
	case err := <-errCh:
		require.ErrorContains(t, err, "not configured")
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not fail on unconfigured ssh address")
	}
}
