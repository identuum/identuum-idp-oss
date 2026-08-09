package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/ratelimit"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

// newLimitedEngine builds a minimal engine with a rate limiter on /probe.
// Gin's trusted-proxy list is set to empty so c.ClientIP() always returns
// RemoteAddr, never the X-Forwarded-For value (tests (a)–(c) require this
// to be deterministic).
func newLimitedEngine(limit ratelimit.RateLimit) *gin.Engine {
	r := gin.New()
	if err := r.SetTrustedProxies([]string{}); err != nil {
		panic(err)
	}
	mw := NewRateLimitMiddleware(limit, "test")
	r.GET("/probe", mw, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func hitProbe(r http.Handler, remoteAddr, xff string) int {
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

// (a) Requests under the per-IP limit pass.
func TestRateLimitMiddleware_UnderLimitPasses(t *testing.T) {
	limit := ratelimit.RateLimit{RequestsPerWindow: 5, WindowDuration: time.Minute}
	r := newLimitedEngine(limit)
	for i := 0; i < 5; i++ {
		if got := hitProbe(r, "10.0.0.1:1234", ""); got != http.StatusOK {
			t.Fatalf("request %d: status=%d, want 200", i+1, got)
		}
	}
	t.Logf("EVIDENCE (a) under-limit: 5 requests passed")
}

// (b) The (N+1)th request from the same IP returns 429.
func TestRateLimitMiddleware_OverLimitReturns429(t *testing.T) {
	limit := ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: time.Minute}
	r := newLimitedEngine(limit)
	if got := hitProbe(r, "10.0.0.2:1234", ""); got != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", got)
	}
	got := hitProbe(r, "10.0.0.2:1234", "")
	t.Logf("EVIDENCE (b) over-limit: second request status=%d (want 429)", got)
	if got != http.StatusTooManyRequests {
		t.Fatalf("second request: status=%d, want 429", got)
	}
}

// (c) A spoofed X-Forwarded-For from a non-trusted source does NOT bypass
// the per-IP limit. Because SetTrustedProxies is empty, c.ClientIP() returns
// RemoteAddr regardless of XFF. Two requests from the same RemoteAddr with
// different spoofed XFF headers are counted in the SAME bucket and the second
// still gets 429.
func TestRateLimitMiddleware_SpoofedXFFDoesNotBypassLimit(t *testing.T) {
	limit := ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: time.Minute}
	r := newLimitedEngine(limit)

	// First request: RemoteAddr=5.6.7.8, XFF=9.9.9.9 (spoofed).
	got1 := hitProbe(r, "5.6.7.8:1234", "9.9.9.9")
	t.Logf("EVIDENCE (c) first request (RemoteAddr=5.6.7.8 XFF=9.9.9.9): status=%d (want 200)", got1)
	if got1 != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", got1)
	}

	// Second request: same RemoteAddr, different spoofed XFF.
	// If XFF were used as the key, this would be a DIFFERENT bucket (8.8.8.8)
	// and would return 200. Returning 429 proves RemoteAddr is the key.
	got2 := hitProbe(r, "5.6.7.8:1234", "8.8.8.8")
	t.Logf("EVIDENCE (c) second request (RemoteAddr=5.6.7.8 XFF=8.8.8.8): status=%d (want 429 — RemoteAddr used, not XFF)", got2)
	if got2 != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF bypassed rate limit: status=%d, want 429", got2)
	}
}

// Zero-value / unconfigured limit → noop (always passes).
func TestRateLimitMiddleware_ZeroLimitIsNoop(t *testing.T) {
	limit := ratelimit.RateLimit{} // zero value: RequestsPerWindow == 0
	r := newLimitedEngine(limit)
	for i := 0; i < 20; i++ {
		if got := hitProbe(r, "10.0.0.3:1234", ""); got != http.StatusOK {
			t.Fatalf("noop request %d: status=%d, want 200", i+1, got)
		}
	}
}

// (refill) After the window elapses, the bucket refills and requests pass
// again — proving the limiter is a real token bucket, not a one-shot gate.
func TestRateLimitMiddleware_RefillsAfterWindow(t *testing.T) {
	// 1 request per 50ms window so the test refills quickly.
	limit := ratelimit.RateLimit{RequestsPerWindow: 1, WindowDuration: 50 * time.Millisecond}
	r := newLimitedEngine(limit)
	if got := hitProbe(r, "10.0.0.9:1234", ""); got != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", got)
	}
	if got := hitProbe(r, "10.0.0.9:1234", ""); got != http.StatusTooManyRequests {
		t.Fatalf("immediate second request: status=%d, want 429", got)
	}
	time.Sleep(70 * time.Millisecond) // > window: bucket refills ≥1 token
	if got := hitProbe(r, "10.0.0.9:1234", ""); got != http.StatusOK {
		t.Fatalf("post-refill request: status=%d, want 200", got)
	}
	t.Logf("EVIDENCE (refill) token bucket refilled after the window elapsed")
}
