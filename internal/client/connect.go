package client

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
)

func (c *Client) runControlStream(ctx context.Context) error {
	controlCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.dcs.Connect(controlCtx)
	if err != nil {
		return err
	}

	// Heartbeats keep the stream alive and surface liveness server-side.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-controlCtx.Done():
				return
			case <-ticker.C:
				if sendErr := stream.Send(&nokkuv1.ConnectRequest{
					Msg: &nokkuv1.ConnectRequest_Heartbeat{Heartbeat: &nokkuv1.Heartbeat{}},
				}); sendErr != nil {
					return
				}
			}
		}
	}()

	// Serialized notification processor, prevents concurrent syncs and panics
	notifyCh := make(chan *nokkuv1.Notification, 1)
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("notification processor panicked", "panic", r)
			}
		}()
		for n := range notifyCh {
			c.handleNotification(ctx, n)
		}
	}()

	// Pump receives through a channel so we can select on context cancellation.
	recvCh := make(chan receiveResult, 1)
	go func() {
		for {
			msg, recvErr := stream.Receive()
			select {
			case recvCh <- receiveResult{msg, recvErr}:
			case <-controlCtx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-controlCtx.Done():
			close(notifyCh)
			<-notifyDone
			return context.Canceled
		case r := <-recvCh:
			if r.err != nil {
				close(notifyCh)
				<-notifyDone
				return r.err
			}
			c.handleServerMessage(ctx, r.msg, notifyCh)
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
	notifyCh chan *nokkuv1.Notification,
) {
	switch m := msg.GetMsg().(type) {
	case *nokkuv1.ConnectResponse_HeartbeatAck:

	case *nokkuv1.ConnectResponse_Notification:
		// Non-blocking send with replace: the worker never falls behind during
		// a burst and the control stream is never blocked. When a notification
		// is already pending, replace it with a full-sync request rather than
		// the latest event.
		select {
		case notifyCh <- m.Notification:
		default:
			select {
			case <-notifyCh:
			default:
			}
			notifyCh <- &nokkuv1.Notification{
				EventType: nokkuv1.Notification_EVENT_TYPE_SYNC_REQUEST.Enum(),
			}
		}

	case *nokkuv1.ConnectResponse_Session:
		go c.startSession(ctx, m.Session)

	default:
		slog.Debug("unexpected server message", "type", fmt.Sprintf("%T", msg.GetMsg()))
	}
}

func (c *Client) handleNotification(ctx context.Context, n *nokkuv1.Notification) {
	switch n.GetEventType() {
	case nokkuv1.Notification_EVENT_TYPE_UNSPECIFIED:
		slog.Debug("unhandled server notification")
	case nokkuv1.Notification_EVENT_TYPE_PRINCIPALS:
		slog.Debug("access rules changed, re-syncing")
		if err := c.syncDaemon(ctx); err != nil {
			slog.Error("sync access rules", "error", err)
		}

	case nokkuv1.Notification_EVENT_TYPE_CERTIFICATES:
		slog.Debug("ssh certificates updated, refreshing")
		if err := c.syncCertificates(ctx); err != nil {
			slog.Error("refresh certificates", "error", err)
		}

	case nokkuv1.Notification_EVENT_TYPE_STATUS:
		if n.GetDaemonId() == c.config.DaemonID {
			status := n.GetStatus()
			if status == nokkuv1.DaemonStatus_DAEMON_STATUS_REJECTED {
				c.config.Clear()
				if err := c.config.Save(); err != nil {
					slog.Error("persist cleared config on rejection", "error", err)
				}
				slog.Error("daemon rejected, exiting")
				os.Exit(1)
			}
		}

	case nokkuv1.Notification_EVENT_TYPE_SYNC_REQUEST:
		slog.Debug("sync requested by server")
		if err := c.syncAll(ctx); err != nil {
			slog.Debug("sync after server request", "error", err)
		}
	}
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
