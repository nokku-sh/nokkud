package sysutil

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
)

// Metadata returns the small, static host description sent on every daemon sync.
func Metadata() map[string]string {
	hostname, _ := os.Hostname()
	return map[string]string{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}
}

// noisePrefixes are virtual interfaces that never make useful SSH endpoints.
// Container, VM, bridge and Kubernetes CNI plumbing.
var noisePrefixes = []string{
	"docker", "veth", "br-", "virbr", "vmnet",
	"vboxnet", "vnic", "vethernet",
	"lo", "dummy", "bond", "teql", "gre", "sit",
	"ip6tnl", "ip6gre",
	"cali", "flannel", "cni",
	"kube", "weave",
	"cilium", "antrea",
	"podman", "containerd",
}

// tunnelPrefixes are mesh/point-to-point VPN interfaces. They are reported
// deliberately. For a decentralized access daemon a WireGuard or Tailscale
// address is often the most reliable way to reach the server.
var tunnelPrefixes = []string{"wg", "tun", "tap", "utun", "ppp"}

// PrivateIPs returns up to two usable IPv4 addresses: physical NICs and
// known mesh-VPN tunnels, skipping loopback and container plumbing.
func PrivateIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ips []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Point-to-point links are usually VPN tunnels. Only the known
		// mesh interfaces make useful endpoints. Anything else
		// point-to-point is skipped.
		if i.Flags&net.FlagPointToPoint != 0 && !hasAnyPrefix(i.Name, tunnelPrefixes) {
			continue
		}

		if isNoiseInterface(i.Name) {
			continue
		}

		var addrs []net.Addr
		addrs, err = i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}

			ip = ip.Unmap()

			if !ip.Is4() {
				continue
			}

			if !isPublicOrPrivateNIC(ip) {
				continue
			}

			ips = append(ips, ip.String())
			if len(ips) >= 2 {
				return ips
			}
		}
	}
	return ips
}

func isNoiseInterface(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "hyper-v") {
		return true
	}
	return hasAnyPrefix(lower, noisePrefixes)
}

func hasAnyPrefix(name string, prefixes []string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isPublicOrPrivateNIC(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	return true
}
