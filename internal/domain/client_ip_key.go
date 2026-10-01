package domain

import "net"

// ClientIPKey is the key a per-client limit counts an IP address under
// (owner ruling 2026-10-01, D-020). An IPv4 address (an IPv4-mapped IPv6
// address included) is its own key, unchanged. An IPv6 address is keyed by its
// /64 — the smallest prefix a single subscriber is normally assigned — so a
// client rotating addresses inside its /64 stays in one bucket. Anything that
// does not parse (an empty IP among them) is returned as is.
func ClientIPKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	prefix := net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}
	return prefix.String()
}
