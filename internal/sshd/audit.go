package sshd

import (
	"golang.org/x/crypto/ssh"

	"github.com/nokku-sh/nokkud/internal/audit"
)

func connEvent(conn ssh.ConnMetadata, typ audit.EventType) audit.Event {
	return audit.Event{
		Type:   typ,
		User:   conn.User(),
		Remote: conn.RemoteAddr().String(),
		Client: string(conn.ClientVersion()),
	}
}
