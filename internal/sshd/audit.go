package sshd

import (
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// newAuditSink opens the local JSONL audit log under the config dir. It
// returns nil when the sink cannot be prepared so the server keeps running
// without audit rather than failing to start.
func newAuditSink() *audit.Sink {
	s, err := audit.New(paths.AuditDir())
	if err != nil {
		slog.Warn("audit log unavailable", "error", err)
		return nil
	}
	return s
}

// emit writes an audit event when an audit sink is configured. Safe to call
// with a nil receiver, so emitters never fail a session.
func (s *Server) emit(ev audit.Event) {
	if s == nil || s.audit == nil {
		return
	}
	s.audit.Emit(ev)
}

// connEvent seeds a connection-related audit event with the common identity
// fields.
func connEvent(conn ssh.ConnMetadata) audit.Event {
	return audit.Event{
		User:   conn.User(),
		Remote: remoteString(conn.RemoteAddr()),
		Client: string(conn.ClientVersion()),
	}
}

func remoteString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// eventWith seeds an event's type and, when provided, principal and error.
func eventWith(ev audit.Event, typ audit.EventType, principal, errMsg string) audit.Event {
	ev.Type = typ
	if principal != "" {
		ev.Principal = principal
	}
	if errMsg != "" {
		ev.Error = errMsg
	}
	return ev
}
