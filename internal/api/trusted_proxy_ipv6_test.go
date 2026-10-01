package api

import "testing"

// D-020: over IPv6 nothing degrades. A proxy listed by an IPv6 CIDR is
// honoured exactly like an IPv4 one: the forwarded client (IPv6 or IPv4) is
// the IP rate limiting, lockout and audit read; a peer outside the CIDR is not
// trusted.
func TestNewOSSEngine_TrustedProxies_IPv6CIDR(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{TrustedProxies: []string{"2001:db8:1::/48"}})
	addIPProbe(e)

	if got := getClientIP(e, "[2001:db8:1::10]:44321", "2001:db8:ff::7"); got != "2001:db8:ff::7" {
		t.Errorf("client IP behind an IPv6 trusted proxy = %q, want the forwarded 2001:db8:ff::7", got)
	}
	if got := getClientIP(e, "[2001:db8:1::10]:44321", "203.0.113.4"); got != "203.0.113.4" {
		t.Errorf("IPv4 client behind an IPv6 trusted proxy = %q, want 203.0.113.4", got)
	}
	if got := getClientIP(e, "[2001:db8:2::10]:44321", "2001:db8:ff::7"); got != "2001:db8:2::10" {
		t.Errorf("untrusted IPv6 peer client IP = %q, want the direct peer 2001:db8:2::10", got)
	}
}

func TestNewOSSEngine_DirectIPv6Peer(t *testing.T) {
	e := NewOSSEngine(OSSRouterDeps{})
	addIPProbe(e)
	if got := getClientIP(e, "[2001:db8:3::5]:5555", ""); got != "2001:db8:3::5" {
		t.Errorf("direct IPv6 peer client IP = %q, want 2001:db8:3::5", got)
	}
}
