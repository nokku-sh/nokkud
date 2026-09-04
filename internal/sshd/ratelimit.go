package sshd

import (
	"net"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

// maxTrackedIPs bounds the per-IP rate limiter cache. Entries beyond it are
// evicted LRU-style, so a distributed flood cannot grow memory unbounded.
const maxTrackedIPs = 4096

// newLimiters builds the per-source-IP connection rate limiter cache.
func newLimiters() *lru.Cache[string, *rate.Limiter] {
	cache, _ := lru.New[string, *rate.Limiter](maxTrackedIPs)
	return cache
}

// allowConn reports whether a new connection from ip fits the configured
// per-IP connection rate. Rate and burst are read from the live tunables on
// every call so SetTunables applies to new connections immediately.
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

// remoteIP extracts the rate-limit key from a connection address.
func remoteIP(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	return addr.String()
}

// banner returns the pre-auth banner reflecting the live tunables, so the
// client learns the policy that will govern its session before authenticating.
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
