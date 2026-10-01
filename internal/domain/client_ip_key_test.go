package domain

import "testing"

// D-020: rate limiting and lockout key an IPv6 client by its /64, so rotating
// addresses inside one /64 does not escape the limit; IPv4 keys are the
// address itself, byte-for-byte as before.
func TestClientIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":                  "203.0.113.7",
		"10.0.0.1":                     "10.0.0.1",
		"::ffff:203.0.113.7":           "203.0.113.7",
		"2001:db8:aa:bb:1:2:3:4":       "2001:db8:aa:bb::/64",
		"2001:db8:aa:bb:ffff:ffff:0:9": "2001:db8:aa:bb::/64",
		"2001:DB8:AA:BB::1":            "2001:db8:aa:bb::/64",
		"::1":                          "::/64",
		"":                             "",
		"not-an-ip":                    "not-an-ip",
	} {
		if got := ClientIPKey(in); got != want {
			t.Errorf("ClientIPKey(%q) = %q, want %q", in, got, want)
		}
	}
	if ClientIPKey("2001:db8:aa:bb::1") == ClientIPKey("2001:db8:aa:bc::1") {
		t.Error("two different /64s share a key")
	}
}
