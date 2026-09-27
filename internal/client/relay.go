package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

const (
	relayDialTimeout = 5 * time.Second
	sessionTTL       = 8 * time.Hour
)

// relayStream is the part of the connect stream the relay uses, so tests can
// drive it without a backend.
type relayStream interface {
	Send(*nokkuv1.DaemonRelayRequest) error
	Receive() (*nokkuv1.DaemonRelayResponse, error)
}

var relayClosed = &nokkuv1.DaemonRelayRequest{
	Msg: &nokkuv1.DaemonRelayRequest_Closed{Closed: &nokkuv1.DaemonRelayClosed{}},
}

// runRelay dials back to the backend and bridges the relay to the local sshd.
// The sshd enforces its own connection cap, so relays need none.
func (c *Client) runRelay(ctx context.Context, req *nokkuv1.RelayOpen) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("relay panicked", "relay", req.GetRelayId(), "panic", r)
		}
	}()
	// Canceling ctx also ends the stream, which unblocks its Receive.
	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	defer cancel()
	stream, err := c.dss.DaemonRelay(ctx)
	if err == nil {
		err = runRelayStream(ctx, stream, loopback(c.sshAddr), req.GetRelayId())
	}
	if err != nil {
		slog.Warn("relay failed", "relay", req.GetRelayId(), "error", err)
	}
}

// runRelayStream bridges one relay stream to sshAddr until either side ends
// or ctx is done.
func runRelayStream(ctx context.Context, stream relayStream, sshAddr, relayID string) error {
	// Ready must be the first message, the backend resolves its pending
	// relay on it. Sending it before the dial makes a dial failure show up as
	// a closed frame instead of a pending timeout.
	if err := stream.Send(&nokkuv1.DaemonRelayRequest{
		Msg: &nokkuv1.DaemonRelayRequest_Ready{Ready: &nokkuv1.DaemonRelayReady{RelayId: &relayID}},
	}); err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: relayDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", sshAddr)
	if err != nil {
		_ = stream.Send(relayClosed)
		return fmt.Errorf("dial local sshd: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	slog.Info("relay connected", "relay", relayID)

	// Backend to sshd. When the backend is done, closing conn ends the pump
	// below as well.
	go func() {
		if inErr := pumpRelayIn(stream, conn); inErr != nil {
			slog.Debug("relay stream ended", "relay", relayID, "error", inErr)
		}
		_ = conn.Close()
	}()

	// sshd to backend. This is the only sender after Ready, so frames never
	// interleave and Closed is always last.
	if err = pumpRelayOut(stream, conn); err != nil {
		slog.Debug("relay conn ended", "relay", relayID, "error", err)
	}
	_ = stream.Send(relayClosed)
	slog.Debug("relay disconnected", "relay", relayID)
	return nil
}

func pumpRelayOut(stream relayStream, conn net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&nokkuv1.DaemonRelayRequest{
				Msg: &nokkuv1.DaemonRelayRequest_Data{Data: buf[:n]},
			}); sendErr != nil {
				return sendErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// pumpRelayIn writes data frames to sshd until a closed frame or an error.
func pumpRelayIn(stream relayStream, conn net.Conn) error {
	for {
		msg, err := stream.Receive()
		if err != nil {
			return err
		}
		switch m := msg.GetMsg().(type) {
		case *nokkuv1.DaemonRelayResponse_Data:
			if _, err = conn.Write(m.Data); err != nil {
				return err
			}
		case *nokkuv1.DaemonRelayResponse_Closed:
			return nil
		}
	}
}

// loopback maps the sshd listen address to one the relay can dial. A
// wildcard bind is reachable on 127.0.0.1.
func loopback(addr netip.AddrPort) string {
	ip := addr.Addr()
	if !ip.IsValid() || ip.IsUnspecified() {
		ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.AddrPortFrom(ip, addr.Port()).String()
}
