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

// clientKeyForTest mirrors internal/api.oauthClientRateLimitKey: bucket by
// the authenticated OAuth client, IP fallback. Kept local so these
// handler-package tests exercise the exact keying the router installs.
func clientKeyForTest(c *gin.Context) string {
	if client, ok := mw.AuthenticatedClientFromContext(c); ok && client != nil {
		return client.ClientID
	}
	return ""
}

func introspectForm(clientID string) *http.Request {
	body := strings.NewReader("token=ANY-TOKEN-VALUE&client_id=" + clientID + "&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/introspection", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// (c)/(e)/(f) INTROSPECTION — per-client, loose. The N+1th request from
// one client is 429 while a *different* client is unaffected (proves the
// limiter keys per authenticated client), the 429 matches the login shape,
// and it leaks no token material.
func TestRateLimit_IntrospectionPerClient(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limit := ratelimit.RateLimit{RequestsPerWindow: 5, WindowDuration: time.Minute}
	RegisterIntrospectionRoutes(r, IntrospectionHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &handlerFakeIntrospector{}, nil),
		Audit:                &audit.Recorder{},
		ClientAuth:           stubAuthnAllowAll{},
		Limiter:              mw.NewRateLimitMiddlewareWithKeyFn(limit, "oauth-introspection", clientKeyForTest),
	})

	// (f) Client A: the first 5 requests pass (introspection returns 200).
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, introspectForm("client-A"))
		if w.Code != http.StatusOK {
			t.Fatalf("client-A req %d: status = %d, want 200 (under limit)", i+1, w.Code)
		}
	}
	// (c)/(e) The 6th from client A is limited: 429, login-parity shape,
	// no token leak.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, introspectForm("client-A"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("client-A 6th: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want \"60\" (login parity)", got)
	}
	if !strings.Contains(w.Body.String(), "Rate limit exceeded") {
		t.Errorf("429 body = %q, want the login-parity message", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ANY-TOKEN-VALUE") {
		t.Errorf("429 body leaked the introspected token: %q", w.Body.String())
	}

	// (per-client isolation) A different client is NOT throttled by A's flood.
	wB := httptest.NewRecorder()
	r.ServeHTTP(wB, introspectForm("client-B"))
	if wB.Code != http.StatusOK {
		t.Errorf("client-B: status = %d, want 200 (per-client keying — A's flood must not limit B)", wB.Code)
	}
}

func tokenForm(clientID string) *http.Request {
	// Missing grant_type → the handler returns 400. Good enough to prove the
	// limiter only ADDS a 429 at the threshold without a full success path.
	body := strings.NewReader("client_id=" + clientID + "&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// (c)/(f) TOKEN — per-client, generous. Below the (here small) threshold
// every request behaves exactly as it would without a limiter; only the
// N+1th is 429. A different client is unaffected. (The generous *default*
// of 120/min is asserted in TestResolveRateLimitConfig_Defaults /
// TestResolveRateLimitConfig_EnvOverride, internal/runtime/ratelimit_wiring_test.go.)
func TestRateLimit_TokenPerClientGenerous(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limit := ratelimit.RateLimit{RequestsPerWindow: 5, WindowDuration: time.Minute}
	tokenSvc := service.NewTokenService(nil, &keyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService: tokenSvc,
		ClientAuth:   tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		Audit:        audit.NoopService{},
		Limiter:      mw.NewRateLimitMiddlewareWithKeyFn(limit, "oauth-token", clientKeyForTest),
	})

	// (f) Baseline: an identical route WITHOUT a limiter returns the normal
	// status for this request — the under-limit path must match it exactly.
	rBase := gin.New()
	RegisterTokenRoutes(rBase, TokenHandlerDeps{
		TokenService: service.NewTokenService(nil, &keyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"}),
		ClientAuth:   tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		Audit:        audit.NoopService{},
	})
	wBase := httptest.NewRecorder()
	rBase.ServeHTTP(wBase, tokenForm("client-A"))
	baseline := wBase.Code

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, tokenForm("client-A"))
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("client-A req %d: 429 under the limit (should not throttle normal refresh)", i+1)
		}
		if w.Code != baseline {
			t.Fatalf("client-A req %d: status = %d, want %d (under-limit must match no-limiter baseline)", i+1, w.Code, baseline)
		}
	}
	// N+1 → 429.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, tokenForm("client-A"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("client-A 6th: status = %d, want 429", w.Code)
	}
	// Per-client isolation.
	wB := httptest.NewRecorder()
	r.ServeHTTP(wB, tokenForm("client-B"))
	if wB.Code == http.StatusTooManyRequests {
		t.Errorf("client-B: 429 — per-client keying broken (A's flood limited B)")
	}
}

// (c)/(e)/(f) PASSWORD-RESET — per IP, tight. N requests from one IP pass;
// the N+1th is 429 with the login-parity shape and no leak. A malformed
// body keeps the service uninvoked so no repo wiring is needed.
func TestRateLimit_PasswordResetPerIP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	limit := ratelimit.RateLimit{RequestsPerWindow: 3, WindowDuration: time.Minute}
	RegisterAccountLifecycleRoutes(r, AccountLifecycleHandlerDeps{
		PasswordReset:        service.NewPasswordResetService(service.PasswordResetServiceConfig{}),
		Audit:                audit.NoopService{},
		PasswordResetLimiter: mw.NewRateLimitMiddleware(limit, "password-reset"),
	})

	resetReq := func() *http.Request {
		// Malformed JSON body → uniform 200 without touching the service.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset-request", strings.NewReader("not-json"))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.7:5555" // fixed source IP → one bucket
		return req
	}

	// (f) The first 3 from this IP pass.
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, resetReq())
		if w.Code != http.StatusOK {
			t.Fatalf("reset req %d: status = %d, want 200 (under limit)", i+1, w.Code)
		}
	}
	// (c)/(e) The 4th is limited.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, resetReq())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("reset 4th: status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want \"60\"", got)
	}
	if !strings.Contains(w.Body.String(), "Rate limit exceeded") {
		t.Errorf("429 body = %q, want login-parity message", w.Body.String())
	}
}
