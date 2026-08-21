package api

// THE-TEETH-SWEEP / ROUTE-RATELIMIT-1. RATE-TOKEN-1's check
// (internal/mw/rate_limit_test.go) mounts the limiter on a synthetic /probe
// route — it proves the MECHANISM, never that the PRODUCTION router keeps a
// limiter on /api/v1/oauth/token. Measured before this test: deleting either
// TokenLimit mount in router.go's mountToken (the CONF-9 IP-keyed
// PreAuthLimiter or the per-client Limiter) left every test in the repo
// green while the endpoint silently reverted to unthrottled.
//
// This test is BEHAVIORAL through the REAL router: NewOSSEngine with a tiny
// configured TokenLimit, then unauthenticated POSTs to /api/v1/oauth/token
// from one IP until the limiter must answer 429. The PreAuth limiter is
// mounted BEFORE the client-auth guard (CONF-9 — a wrong client_secret must
// still be throttled), so unauthenticated posts consume it.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// RULE: ROUTE-RATELIMIT-1
func TestTokenRoute_RealRouterEnforcesConfiguredLimit(t *testing.T) {
	const limit = 3
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	engine := NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		TokenService:    tokenSvc,
		OAuthClientAuth: stubClientAuth{},
		RateLimitConfig: ratelimit.RateLimitConfig{
			TokenLimit: ratelimit.RateLimit{RequestsPerWindow: limit, WindowDuration: time.Minute},
		},
	})

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token",
			strings.NewReader("grant_type=client_credentials"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:44444" // one stable client IP
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Code
	}

	// PREMISE (non-emptiness): within the window the route must answer,
	// and must NOT already be throttled — otherwise the 429 assertion
	// below could pass vacuously against a broken always-429 router.
	codes := make([]int, 0, limit+1)
	for i := 0; i < limit; i++ {
		code := post()
		codes = append(codes, code)
		if code == http.StatusTooManyRequests {
			t.Fatalf("PREMISE broken: request %d/%d already 429 — the window never admitted traffic (codes=%v)", i+1, limit, codes)
		}
		if code == http.StatusNotFound {
			t.Fatalf("PREMISE broken: /api/v1/oauth/token not mounted (404) — the pin has drifted off its target")
		}
	}

	// Past the configured limit the REAL router must throttle.
	over := post()
	codes = append(codes, over)
	if over != http.StatusTooManyRequests {
		t.Fatalf("request %d exceeded TokenLimit=%d yet the production router answered %d, want 429 — the /oauth/token limiter is unmounted (codes=%v)", limit+1, limit, over, codes)
	}
}
