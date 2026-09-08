package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

const (
	relayIdleTimeout = 5 * time.Minute
	relayDialTimeout = 5 * time.Second

	sessionTTL            = 8 * time.Hour
	maxConcurrentSessions = 100
)

// relayStream is the subset of the connect bidi stream the relay pumps use,
// kept as a seam so tests can drive the pumps without a backend.
type relayStream interface {
	Send(*nokkuv1.DaemonRelayRequest) error
	Receive() (*nokkuv1.DaemonRelayResponse, error)
}

func (c *Client) startRelay(ctx context.Context, req *nokkuv1.RelayOpen) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("relay handler panicked", "id", req.GetRelayId(), "panic", r)
		}
	}()

	if err := c.runRelay(ctx, req); err != nil {
		slog.Error("relay failed", "id", req.GetRelayId(), "error", err)
	}
}

// runRelay bridges one user SSH connection to the daemon's own sshd over a
// DaemonRelay stream. It ends on sshd closing the connection, a stream
// error, a server-issued close, idle timeout, or TTL.
//

func (c *Client) runRelay(ctx context.Context, req *nokkuv1.RelayOpen) error {
	select {
	case c.sessionSlots <- struct{}{}:
		defer func() { <-c.sessionSlots }()
	default:
		return errors.New("too many sessions")
	}

	stream, err := c.dss.DaemonRelay(ctx)
	if err != nil {
		return err
	}
	return runRelayStream(ctx, stream, c.config.SSHAddr, req.GetRelayId())
}

// runRelayStream bridges one opened relay stream to the daemon's own sshd.
// It ends on sshd closing the connection, a stream error, a server-issued
// close, idle timeout, or TTL.
//

func runRelayStream(ctx context.Context, stream relayStream, sshAddr, relayID string) error {
	logger := slog.With("relay", relayID)

	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	defer cancel()

	// Ready goes out before dialing sshd: the backend resolves its pending
	// relay on the ready frame, so a dial failure below surfaces there as a
	// closed frame instead of a pending timeout. It must be the stream's
	// first message: the backend correlates the pending relay by it.
	id := relayID
	if err := stream.Send(&nokkuv1.DaemonRelayRequest{
		Msg: &nokkuv1.DaemonRelayRequest_Ready{Ready: &nokkuv1.DaemonRelayReady{RelayId: &id}},
	}); err != nil {
		return err
	}
	logger.Info("relay connected")

	sendGate := make(chan struct{}, 1)

	conn, err := dialSSHd(ctx, sshAddr)
	if err != nil {
		// The pumps have not started, so the gate only bounds the send.
		select {
		case sendGate <- struct{}{}:
			_ = stream.Send(&nokkuv1.DaemonRelayRequest{
				Msg: &nokkuv1.DaemonRelayRequest_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
			})
			<-sendGate
		case <-time.After(2 * time.Second):
		}
		return fmt.Errorf("dial local sshd: %w", err)
	}
	defer func() { _ = conn.Close() }()

	idleTimer := time.NewTimer(relayIdleTimeout)
	defer idleTimer.Stop()
	var idleMu sync.Mutex
	resetIdle := func() {
		idleMu.Lock()
		defer idleMu.Unlock()
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(relayIdleTimeout)
	}

	done := make(chan struct{})
	var doneOnce sync.Once
	finish := func() { doneOnce.Do(func() { close(done) }) }

	var pumps sync.WaitGroup
	pumps.Go(func() {
		defer recoverLog("relay conn pump")
		if pumpErr := pumpRelayOut(ctx, stream, conn, sendGate, resetIdle); pumpErr != nil {
			logger.Debug("relay conn pump ended", "error", pumpErr)
		}
		finish()
	})
	pumps.Go(func() {
		defer recoverLog("relay stream pump")
		if pumpErr := pumpRelayIn(stream, conn, resetIdle); pumpErr != nil {
			logger.Debug("relay stream pump ended", "error", pumpErr)
		}
		finish()
	})

	go func() {
		defer recoverLog("relay idle watcher")
		select {
		case <-ctx.Done():
		case <-idleTimer.C:
			logger.Info("relay idle timeout, closing")
		}
		finish()
	}()

	<-done

	// Send the close while the stream context is still alive: cleanup
	// cancels ctx and a Send on a canceled context is rejected locally. The
	// gate token is drained rather than returned, so a pump that read sshd
	// traffic just before teardown can never send a data frame after the
	// closed frame.
	select {
	case sendGate <- struct{}{}:
		_ = stream.Send(&nokkuv1.DaemonRelayRequest{
			Msg: &nokkuv1.DaemonRelayRequest_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
		})
		_ = conn.Close()
		cancel()
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		cancel()
	}
	pumps.Wait()

	logger.Debug("relay disconnected")
	return nil
}

// pumpRelayOut forwards sshd traffic to the stream as data frames. It stops
// on conn EOF, a send error, or ctx cancellation.
func pumpRelayOut(
	ctx context.Context,
	stream relayStream,
	conn net.Conn,
	gate chan struct{},
	resetIdle func(),
) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			resetIdle()
			select {
			case gate <- struct{}{}:
				sendErr := stream.Send(&nokkuv1.DaemonRelayRequest{
					Msg: &nokkuv1.DaemonRelayRequest_Data{Data: buf[:n]},
				})
				<-gate
				if sendErr != nil {
					return sendErr
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// pumpRelayIn writes received data frames to sshd. It stops on a closed
// frame, a receive error, or a write error.
func pumpRelayIn(stream relayStream, conn net.Conn, resetIdle func()) error {
	for {
		msg, err := stream.Receive()
		if err != nil {
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.DaemonRelayResponse_Data:
			resetIdle()
			if _, writeErr := conn.Write(m.Data); writeErr != nil {
				return writeErr
			}
		case *nokkuv1.DaemonRelayResponse_Closed:
			return nil
		}
	}
}

// dialSSHd connects to the daemon's own sshd, mapping the configured listen
// address to a dialable loopback target.
func dialSSHd(ctx context.Context, sshAddr string) (net.Conn, error) {
	dialAddr, err := relayDialAddr(sshAddr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	return dialer.DialContext(ctx, "tcp", dialAddr)
}

// relayDialAddr resolves where the daemon's own sshd listens. A wildcard
// bind host means loopback, a specific bind address is used as is. An empty
// address is a misconfiguration: main installs the default before serving,
// so empty here means the config was cleared mid-run.
func relayDialAddr(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("ssh listen address is not configured")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort("127.0.0.1", sshPort(addr)), nil
	}
	switch host {
	case "", "*", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
