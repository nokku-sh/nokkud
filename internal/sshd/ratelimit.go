package sshd

import (
	"net"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

// maxTrackedIPs bounds the per-IP limiter cache so a distributed flood cannot
// grow memory unbounded.
const maxTrackedIPs = 4096

func newLimiters() *lru.Cache[string, *rate.Limiter] {
	cache, _ := lru.New[string, *rate.Limiter](maxTrackedIPs)
	return cache
}

// allowConn reports whether a connection from ip fits its per-IP limit. Rate
// and burst come from the live tunables so SetTunables applies immediately.
func (s *Server) allowConn(ip string) bool {
	t := s.tun.Load()
	if t.ConnRate <= 0 {
		return true
	}
	lim, ok := s.limiters.Get(ip)
	if !ok {
		lim = rate.NewLimiter(rate.Limit(t.ConnRate), max(t.ConnRateBurst, 1))
		s.limiters.Add(ip, lim)
	}
	lim.SetLimit(rate.Limit(t.ConnRate))
	lim.SetBurst(max(t.ConnRateBurst, 1))
	return lim.Allow()
}

func remoteIP(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}

// banner returns the pre-auth banner reflecting the live tunables, so the
// client learns its policy before authenticating.
func (s *Server) banner() string {
	t := s.tun.Load()
	if !t.Banner {
		return ""
	}
	var lines []string
	if t.Record {
		lines = append(lines, "This session is recorded and audited.")
	}
	if t.AllowForwarding {
		lines = append(lines, "Port forwarding is available.")
	}
	if t.AllowAgentForwarding {
		lines = append(lines, "Agent forwarding is available.")
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
