package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// CONF-9: the /introspection and /token limiters sit BEHIND the aborting auth
// guard, so neither throttles a wrong client_secret. mw.RequireOAuthClient
// aborts on every authentication failure, the limiter never runs, and an
// attacker grinding secrets is met by bcrypt at full speed with no 429 ever.
//
// /revoke does not have this defect — CONF-7 mounted its limiter FIRST, and
// the shared key fn falls back to c.ClientIP() pre-auth (rate_limit.go:52-53).
// These tests demand the same property here, via a pre-auth IP-keyed limiter
// IN FRONT of the guard (owner ruling, THE-EMPTY-QUEUE order C): the post-auth
// per-client limiter stays, because pre-auth there is no client to key on and
// post-auth IP would collapse NAT'd clients into one bucket.
func TestRateLimit_IntrospectionThrottlesUnauthenticated(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limit := ratelimit.RateLimit{RequestsPerWindow: 3, WindowDuration: time.Minute}
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &handlerFakeIntrospector{}, nil),
		Audit:                &audit.Recorder{},
		ClientAuth:           stubAuthnRejectAll{},
		PreAuthLimiter:       mw.NewRateLimitMiddleware(limit, "oauth-introspection-preauth"),
	})

	// CONTROL: under the limit, a wrong secret must still be a 401 — the
	// pre-auth limiter must not change what an ordinary failure looks like.
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, introspectForm("grinder"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("CONTROL FAILED: unauthenticated req %d = %d, want 401 — this test proves "+
				"nothing unless ordinary auth failures still 401", i+1, w.Code)
		}
	}

	// The 4th unauthenticated request from the same IP must be THROTTLED, not
	// handed to the auth stack again.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, introspectForm("grinder"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th unauthenticated request = %d, want 429 — the limiter sits behind the "+
			"aborting auth guard, so a wrong client_secret is never throttled", w.Code)
	}
}

func TestRateLimit_TokenThrottlesUnauthenticated(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limit := ratelimit.RateLimit{RequestsPerWindow: 3, WindowDuration: time.Minute}
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService:   &service.TokenService{},
		ClientAuth:     stubAuthnRejectAll{},
		Audit:          &audit.Recorder{},
		PreAuthLimiter: mw.NewRateLimitMiddleware(limit, "oauth-token-preauth"),
	})

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, tokenForm("grinder"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("CONTROL FAILED: unauthenticated req %d = %d, want 401", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, tokenForm("grinder"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th unauthenticated request = %d, want 429 — /token never throttles a wrong "+
			"client_secret", w.Code)
	}
}
