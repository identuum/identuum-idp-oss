package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// CONF-7 teeth: /api/v1/oauth/revoke must throttle a WRONG client_secret.
//
// The defect this pins: mw.RequireOAuthClient ABORTS on every auth failure
// (respondInvalidClient; return), so a limiter mounted AFTER it — the shape
// token.go and introspection.go use — never runs for a failed authentication.
// A wrong secret therefore returns 401 forever, with no bound at all: an
// unthrottled guess-and-check oracle against client_secret.
//
// The fix mounts the limiter BEFORE the guard on this route. The same
// oauthClientRateLimitKey helper is reused: it returns "" pre-auth, which
// makes NewRateLimitMiddlewareWithKeyFn fall back to IP bucketing — exactly
// what is wanted for an attacker who has not authenticated.
func newRevocationRateLimitEngine(t *testing.T, limiter gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{}, nil),
		SessionRevoker:       &service.RecorderSessionRevoker{},
		// Every credential is rejected: this is the attacker's view.
		ClientAuth: rejectAllClientAuth{},
		Audit:      &audit.Recorder{},
		Limiter:    limiter,
	})
	return r
}

func postRevokeWrongSecret(t *testing.T, r *gin.Engine) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke",
		strings.NewReader("token=whatever"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("attacker-client", "wrong-secret-guess")
	req.RemoteAddr = "203.0.113.9:41000" // one attacker IP, so one bucket
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// TestRevocation_WrongSecretFloodIsThrottled floods the endpoint past the
// configured limit with a wrong secret and requires a 429. Without the
// before-the-guard mount this is 401 forever — the oracle.
func TestRevocation_WrongSecretFloodIsThrottled(t *testing.T) {
	const limit = 120
	limiter := mw.NewRateLimitMiddlewareWithKeyFn(
		ratelimit.RateLimit{RequestsPerWindow: limit, WindowDuration: time.Minute},
		"oauth-revocation-test",
		func(c *gin.Context) string { return "" }, // pre-auth: IP fallback
	)
	r := newRevocationRateLimitEngine(t, limiter)

	// Every request inside the window is refused for the RIGHT reason (401,
	// bad credential) — the limiter must not mask a real auth decision.
	for i := 0; i < limit; i++ {
		if got := postRevokeWrongSecret(t, r); got != http.StatusUnauthorized {
			t.Fatalf("request %d/%d: status = %d, want 401 (auth must still decide inside the limit)", i+1, limit, got)
		}
	}

	// The one past the limit must be throttled, not merely refused again.
	if got := postRevokeWrongSecret(t, r); got != http.StatusTooManyRequests {
		t.Fatalf("request %d (past the %d/min limit): status = %d, want 429 — a wrong client_secret is an UNTHROTTLED oracle at /revoke", limit+1, limit, got)
	}
}

// TestRevocation_NilLimiterUnchanged pins that the new field is nil-safe: with
// no limiter configured the route behaves exactly as before (401 forever, no
// panic), so an operator who never sets the env vars sees no change.
func TestRevocation_NilLimiterUnchanged(t *testing.T) {
	r := newRevocationRateLimitEngine(t, nil)
	for i := 0; i < 3; i++ {
		if got := postRevokeWrongSecret(t, r); got != http.StatusUnauthorized {
			t.Fatalf("nil limiter, request %d: status = %d, want 401", i+1, got)
		}
	}
}
