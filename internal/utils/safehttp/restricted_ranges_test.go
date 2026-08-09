package safehttp

import (
	"net"
	"testing"
)

// P3-7: the special-purpose ranges isRestrictedIP did not cover. None is
// routable on the public internet, so an outbound request reaching one is
// either a misconfiguration or an SSRF pivot — and CGNAT in particular is live
// address space inside many hosting providers, not a curiosity.
func TestIsRestrictedIP_CoversSpecialPurposeRanges(t *testing.T) {
	// CONTROL: ranges already covered must stay covered. A row of failures
	// below means nothing if the function has stopped answering entirely.
	for _, ctl := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0"} {
		if !isRestrictedIP(net.ParseIP(ctl)) {
			t.Fatalf("CONTROL FAILED: %s is no longer restricted — the function is broken, "+
				"so the results below would be meaningless", ctl)
		}
	}

	for _, tc := range []struct{ ip, why string }{
		{"100.64.0.1", "RFC 6598 CGNAT 100.64.0.0/10 — live inside many hosting providers"},
		{"100.127.255.254", "RFC 6598 CGNAT upper edge"},
		{"192.0.0.1", "RFC 6890 IETF protocol assignments 192.0.0.0/24"},
		{"198.18.0.1", "RFC 2544 benchmarking 198.18.0.0/15"},
		{"192.0.2.1", "RFC 5737 documentation TEST-NET-1"},
		{"198.51.100.1", "RFC 5737 documentation TEST-NET-2"},
		{"203.0.113.1", "RFC 5737 documentation TEST-NET-3"},
		{"240.0.0.1", "RFC 1112 reserved 240.0.0.0/4"},
		{"2001:db8::1", "RFC 3849 IPv6 documentation 2001:db8::/32"},
	} {
		if !isRestrictedIP(net.ParseIP(tc.ip)) {
			t.Errorf("%s NOT restricted — %s", tc.ip, tc.why)
		}
	}

	// And routable space must still be allowed, or the fix is a denial of service.
	for _, ok := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if isRestrictedIP(net.ParseIP(ok)) {
			t.Errorf("%s was restricted; public routable addresses must still be reachable", ok)
		}
	}
}
