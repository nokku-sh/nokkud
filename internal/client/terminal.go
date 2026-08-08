package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/aymanbagabas/go-pty"
	"golang.org/x/time/rate"

	nokkuv1 "github.com/nokku-sh/nokkud/internal/gen/nokku/v1"
	"github.com/nokku-sh/nokkud/internal/recorder"
	"github.com/nokku-sh/nokkud/internal/sysutil"
)

const (
	sessionTTL            = 8 * time.Hour
	idleTimeout           = 30 * time.Minute
	stdoutRate            = 512 * 1024
	stdoutBurst           = 64 * 1024
	maxConcurrentSessions = 100
)

// recoverLog catches panics in goroutines so a single bug never kills the daemon.
func recoverLog(desc string) {
	if r := recover(); r != nil {
		slog.Error("goroutine panicked", "component", desc, "panic", r)
	}
}

// runPTYSession opens a bidi stream for one PTY session. The session ends on
// PTY exit, idle timeout, TTL expiry, a server-issued Close, or any stream error.
//
//nolint:funlen,gocognit
func (c *Client) runPTYSession(ctx context.Context, req *nokkuv1.Session) error {
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
	stream, err := c.dss.Session(ctx)
	if err != nil {
		_ = ptmx.Close()
		return err
	}

	shell := sysutil.UserShell(sysUser)
	cmd := ptmx.Command(shell)
	cmd.Args[0] = "-" + filepath.Base(shell)
	cmd.Dir = sysUser.HomeDir
	cmd.Env = sysutil.CmdEnv(sysUser, shell)
	cmd.SysProcAttr, err = sysutil.SysProcAttr(sysUser)
	if err != nil {
		_ = ptmx.Close()
		return err
	}

	if err = cmd.Start(); err != nil {
		_ = ptmx.Close()
		return err
	}

	logger.Info("session started")

	var rec *recorder.Recorder
	if c.config.DaemonConfig.GetRecordSessions() {
		shortID := sessionID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		rec, err = recorder.New(c.paths, recorder.Options{
			Width:     80,
			Height:    24,
			Title:     fmt.Sprintf("%s@%s", sysUser.Username, sessionID),
			Label:     fmt.Sprintf("%s-%s", sysUser.Username, shortID),
			SessionID: sessionID,
		})
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
				rec.Close()
			}
		})
	}
	defer cleanup()

	rr := &nokkuv1.SessionReady{
		SessionId: &sessionID,
		Username:  &username,
		UserId:    &userID,
	}
	if err = stream.Send(&nokkuv1.SessionRequest{
		Msg: &nokkuv1.SessionRequest_Ready{Ready: rr},
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
	// over; cleanup then runs (idempotently) and we send an Exited notice.
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
			var msg *nokkuv1.SessionResponse
			msg, err = stream.Receive()
			if err != nil {
				finish()
				return
			}
			switch m := msg.GetMsg().(type) {
			case *nokkuv1.SessionResponse_Stdin:
				resetIdle()
				// Omit input while the pty has echo disabled (password prompts).
				if rec != nil && sysutil.EchoEnabled(ptmx.Fd()) {
					rec.RecordInput(m.Stdin)
				}
				if _, err = ptmx.Write(m.Stdin); err != nil {
					logger.Warn("PTY write failed", "error", err)
				}
			case *nokkuv1.SessionResponse_Resize:
				w, h := m.Resize.GetWidth(), m.Resize.GetHeight()
				if err = ptmx.Resize(int(w), int(h)); err != nil {
					logger.Warn("Terminal resize failed", "error", err)
				}
				if rec != nil {
					rec.RecordResize(int(w), int(h))
				}
			case *nokkuv1.SessionResponse_Close:
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
			var n int
			n, err = ptmx.Read(buf)
			if n > 0 {
				resetIdle()
				chunk := buf[:n]
				if rec != nil {
					rec.RecordOutput(chunk)
				}
				if err = limiter.WaitN(ctx, n); err != nil {
					return
				}
				if err = stream.Send(&nokkuv1.SessionRequest{
					Msg: &nokkuv1.SessionRequest_Stdout{Stdout: chunk},
				}); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	cleanup()
	logger.Debug("session disconnected")

	_ = stream.Send(&nokkuv1.SessionRequest{
		Msg: &nokkuv1.SessionRequest_Exited{Exited: &nokkuv1.SessionEnded{}},
	})
	return nil
}
