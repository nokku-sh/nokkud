package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

const heartbeatInterval = 5 * time.Minute

// runControlStream keeps the control stream open until ctx is cancelled.
// The stream is the daemon's only periodic contact. An immediate heartbeat
// reports our state version, later heartbeats keep it alive, and the server
// pushes state updates. A fatal error (daemon rejection) is returned so Run
// can surface it instead of reconnecting.
func (c *Client) runControlStream(ctx context.Context, onConnect func()) error {
	controlCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.dcs.Connect(controlCtx)
	if err != nil {
		return err
	}

	if onConnect != nil {
		onConnect()
	}

	go c.sendHeartbeats(controlCtx, stream)

	recvCh := make(chan receiveResult, 1)
	go pumpReceives(controlCtx, stream, recvCh)

	for {
		select {
		case <-controlCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		case r := <-recvCh:
			if r.err != nil {
				return r.err
			}
			if handleErr := c.handleServerMessage(ctx, r.msg); handleErr != nil {
				if errors.Is(handleErr, errDaemonRejected) {
					cancel()
					return handleErr
				}
				slog.Warn("failed to handle server message", "error", handleErr)
			}
		}
	}
}

// sendHeartbeats sends an immediate heartbeat and then keeps the stream alive.
func (c *Client) sendHeartbeats(
	ctx context.Context,
	stream *connect.BidiStreamForClientSimple[nokkuv1.ConnectRequest, nokkuv1.ConnectResponse],
) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	send := func() bool {
		version := c.cache.GetStateVersion()
		return stream.Send(&nokkuv1.ConnectRequest{
			Msg: &nokkuv1.ConnectRequest_Heartbeat{
				Heartbeat: &nokkuv1.Heartbeat{StateVersion: &version},
			},
		}) == nil
	}

	send()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

// pumpReceives forwards stream messages to recvCh so the run loop can
// select on context cancellation alongside incoming messages.
func pumpReceives(
	ctx context.Context,
	stream *connect.BidiStreamForClientSimple[nokkuv1.ConnectRequest, nokkuv1.ConnectResponse],
	recvCh chan receiveResult,
) {
	for {
		msg, err := stream.Receive()
		select {
		case recvCh <- receiveResult{msg, err}:
		case <-ctx.Done():
			return
		}
	}
}

type receiveResult struct {
	msg *nokkuv1.ConnectResponse
	err error
}

func (c *Client) handleServerMessage(
	ctx context.Context,
	msg *nokkuv1.ConnectResponse,
) error {
	switch m := msg.GetMsg().(type) {
	case *nokkuv1.ConnectResponse_HeartbeatAck:
		return c.reconcile(ctx, m.HeartbeatAck.GetStateVersion())
	case *nokkuv1.ConnectResponse_StateUpdate:
		return c.reconcile(ctx, m.StateUpdate.GetStateVersion())
	case *nokkuv1.ConnectResponse_Session:
		go c.startSession(ctx, m.Session)
	default:
		slog.Debug("unexpected server message", "type", fmt.Sprintf("%T", msg.GetMsg()))
	}
	return nil
}

// reconcile re-syncs when the server's state version differs from ours.
func (c *Client) reconcile(ctx context.Context, serverVersion int64) error {
	if serverVersion == c.cache.GetStateVersion() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	if err := c.syncDaemon(ctx); err != nil {
		slog.Warn("sync after state update", "error", err)
		return err
	}
	return nil
}

func (c *Client) startSession(ctx context.Context, req *nokkuv1.Session) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("session handler panicked", "id", req.GetSessionId(), "panic", r)
		}
	}()

	if err := c.runPTYSession(ctx, req); err != nil {
		slog.Error("session failed", "id", req.GetSessionId(), "error", err)
	}
}
