package mw

import (
	"net/http"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// D-020: an IPv6 client is limited by its /64. Rotating the interface
// identifier inside one /64 must not reach a fresh bucket; a different /64
// does; IPv4 addresses keep one bucket each, as before.
func TestRateLimitMiddleware_IPv6RotationInsideA64StaysLimited(t *testing.T) {
	limit := ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: time.Minute}
	r := newLimitedEngine(limit)
	if got := hitProbe(r, "[2001:db8:aa:bb::1]:1234", ""); got != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", got)
	}
	if got := hitProbe(r, "[2001:db8:aa:bb:dead:beef:0:2]:1234", ""); got != http.StatusTooManyRequests {
		t.Fatalf("a second address in the same /64: status=%d, want 429", got)
	}
	if got := hitProbe(r, "[2001:db8:aa:bc::1]:1234", ""); got != http.StatusOK {
		t.Fatalf("a different /64: status=%d, want 200", got)
	}
}

func TestRateLimitMiddleware_IPv4KeysUnchanged(t *testing.T) {
	limit := ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: time.Minute}
	r := newLimitedEngine(limit)
	if got := hitProbe(r, "198.51.100.1:1234", ""); got != http.StatusOK {
		t.Fatalf("first IPv4 address: status=%d, want 200", got)
	}
	if got := hitProbe(r, "198.51.100.2:1234", ""); got != http.StatusOK {
		t.Fatalf("a neighbouring IPv4 address: status=%d, want 200 (IPv4 is not grouped)", got)
	}
	if got := hitProbe(r, "198.51.100.1:1234", ""); got != http.StatusTooManyRequests {
		t.Fatalf("the first address again: status=%d, want 429", got)
	}
}
