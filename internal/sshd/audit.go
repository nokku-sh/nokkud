package sshd

import (
	"crypto/rand"
	"encoding/hex"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
)

// newSessionID returns a random hex string used to correlate audit events for
// one session.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
