package sshd

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// newAuditSink opens the local JSONL audit log under the config dir. It
// returns nil when the sink cannot be prepared so the server keeps running
// without audit rather than failing to start.
func newAuditSink(p paths.Paths) *audit.Sink {
	s, err := audit.New(p.AuditDir)
	if err != nil {
		slog.Warn("audit log unavailable", "error", err)
		return nil
	}
	return s
}

// newSessionID returns a random UUID used to correlate audit events and
// recordings for one session. The backend expects canonical dashed UUIDs
// (the recordings table stores session ids in a UUID column), so the raw
// bytes are formatted as RFC 4122 version 4.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(b), nil
}

// formatUUID renders 16 random bytes as a dashed, lower-case UUID.
func formatUUID(b []byte) string {
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
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
