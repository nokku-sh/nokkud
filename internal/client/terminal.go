package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/ptysession"
	"github.com/nokku-sh/nokkud/internal/recording"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

const (
	sessionTTL            = 8 * time.Hour
	idleTimeout           = 30 * time.Minute
	stdoutRate            = 512 * 1024
	stdoutBurst           = 64 * 1024
	maxConcurrentSessions = 100
)

// runPTYSession opens a bidi stream for one PTY session. The session ends on
// PTY exit, idle timeout, TTL expiry, a server-issued Close, or any stream
// error.
//
//nolint:funlen,gocognit,cyclop // is fine
func (c *Client) runPTYSession(ctx context.Context, req *nokkuv1.DaemonSession) error {
	sessionID := req.GetSessionId()
	username := req.GetUsername()
	userID := req.GetUserId()

	select {
	case c.sessionSlots <- struct{}{}:
		defer func() { <-c.sessionSlots }()
	default:
		return fmt.Errorf("too many sessions")
	}

	if ok := c.cache.HasUUID(username, userID); !ok {
		return errors.New("unauthorized")
	}

	sysUser, err := sysutil.LookupUser(username)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, sessionTTL)
	defer cancel()

	logger := slog.With("id", sessionID, "user", sysUser.Username)

	ptmx, err := pty.New()
	if err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	if err = ptmx.Resize(80, 24); err != nil {
		_ = ptmx.Close()
		return err
	}

	// Open the session stream before spawning the shell: if the backend
	// refuses the session there is no stray process to reap.
	stream, err := c.dss.DaemonSession(ctx)
	if err != nil {
		_ = ptmx.Close()
		return err
	}

	shell := sysutil.UserShell(sysUser)
	cmd := ptmx.Command(shell)
	if err = ptysession.Configure(
		cmd,
		sysUser,
		shell,
		"",
		sysutil.CmdEnv(sysUser, shell),
	); err != nil {
		_ = ptmx.Close()
		return err
	}

	if err = cmd.Start(); err != nil {
		_ = ptmx.Close()
		return err
	}

	logger.Info("session started")

	var rec *recording.Recorder
	if c.cache.RecordSessions() {
		shortID := sessionID[:min(len(sessionID), 8)]
		rec, err = recording.NewSessionRecorder(
			ctx,
			c.rc,
			recording.Options{
				Width:     80,
				Height:    24,
				Title:     fmt.Sprintf("%s@%s", sysUser.Username, sessionID),
				Label:     fmt.Sprintf("%s-%s", sysUser.Username, shortID),
				SessionID: sessionID,
				Username:  sysUser.Username,
			},
		)
		if err != nil {
			logger.Debug("session recording unavailable", "reason", err)
		}
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			cancel()
			_ = ptmx.Close()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
			if rec != nil {
				if cmd.ProcessState != nil {
					rec.RecordExit(cmd.ProcessState.ExitCode())
				}
				rec.Close()
			}
		})
	}
	defer cleanup()

	rr := &nokkuv1.DaemonSessionReady{
		SessionId: &sessionID,
		Username:  &username,
		UserId:    &userID,
	}
	// Connect streams forbid calling Send concurrently with itself. The
	// stdout pump and the final exit notice therefore serialize through
	// sendGate (a cap-1 channel, so the exit notice can time out instead of
	// blocking teardown behind a wedged stream). Ready goes out before the
	// pumps start and needs no gate.
	sendGate := make(chan struct{}, 1)
	if err = stream.Send(&nokkuv1.DaemonSessionRequest{
		Msg: &nokkuv1.DaemonSessionRequest_Ready{Ready: rr},
	}); err != nil {
		return err
	}

	idleTimer := time.NewTimer(idleTimeout)
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
		idleTimer.Reset(idleTimeout)
	}

	// done is closed once by whichever goroutine first notices the session is
	// over. Cleanup then runs (idempotently) and we send an Exited notice.
	done := make(chan struct{})
	var doneOnce sync.Once
	finish := func() { doneOnce.Do(func() { close(done) }) }

	go func() {
		defer recoverLog("session idle watcher")
		select {
		case <-ctx.Done():
		case <-idleTimer.C:
			logger.Info("session idle timeout, closing")
		}
		finish()
	}()

	go func() {
		defer recoverLog("session receive")
		for {
			msg, recvErr := stream.Receive()
			if recvErr != nil {
				finish()
				return
			}
			switch m := msg.GetMsg().(type) {
			case *nokkuv1.DaemonSessionResponse_Stdin:
				resetIdle()
				// Omit input while the pty has echo disabled (password prompts).
				if rec != nil && sysutil.EchoEnabled(ptmx.Fd()) {
					rec.RecordInput(m.Stdin)
				}
				if _, writeErr := ptmx.Write(m.Stdin); writeErr != nil {
					logger.Warn("PTY write failed", "error", writeErr)
				}
			case *nokkuv1.DaemonSessionResponse_Resize:
				w, h := m.Resize.GetWidth(), m.Resize.GetHeight()
				if resizeErr := ptmx.Resize(int(w), int(h)); resizeErr != nil {
					logger.Warn("Terminal resize failed", "error", resizeErr)
				}
				if rec != nil {
					rec.RecordResize(int(w), int(h))
				}
			case *nokkuv1.DaemonSessionResponse_Close:
				logger.Info("session closed by server")
				finish()
				return
			}
		}
	}()

	// Any read or send error ends the session via the deferred finish().
	go func() {
		defer recoverLog("session stdout sender")
		defer finish()
		limiter := rate.NewLimiter(rate.Limit(stdoutRate), stdoutBurst)
		buf := make([]byte, 32*1024)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				resetIdle()
				chunk := buf[:n]
				if rec != nil {
					rec.RecordOutput(chunk)
				}
				if waitErr := limiter.WaitN(ctx, n); waitErr != nil {
					return
				}
				select {
				case sendGate <- struct{}{}:
					sendErr := stream.Send(&nokkuv1.DaemonSessionRequest{
						Msg: &nokkuv1.DaemonSessionRequest_Stdout{Stdout: chunk},
					})
					<-sendGate
					if sendErr != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	<-done
	// Report the exit while the stream context is still alive: cleanup
	// cancels it, and a Send on a canceled context is rejected locally, so
	// the backend would never learn the PTY ended. Bounded so a wedged
	// stream cannot stall shutdown; the backend also ends the session when
	// the stream itself tears down.
	select {
	case sendGate <- struct{}{}:
		_ = stream.Send(&nokkuv1.DaemonSessionRequest{
			Msg: &nokkuv1.DaemonSessionRequest_Exited{Exited: &nokkuv1.DaemonSessionEnded{}},
		})
		<-sendGate
	case <-time.After(2 * time.Second):
	}
	cleanup()
	logger.Debug("session disconnected")
	return nil
}
