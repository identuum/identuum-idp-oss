package runtime

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func credentialPost(path, remote string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remote
	return req
}

// Every POST route where a caller proves a secret shares one per-address bucket:
// the lockout counts recorded failures, this bounds how fast an address may try at
// all. Driven through the real assembled engine.
func TestNewOSSEngine_CredentialPostsShareAPerAddressLimit(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_CREDENTIAL_REQUESTS", "3")
	e := api.NewOSSEngine(api.OSSRouterDeps{
		ClaimService:    service.NewClaimService(service.ClaimServiceConfig{}),
		RateLimitConfig: resolveRateLimitConfig(nil),
	})
	serve := func(path, remote string) int {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, credentialPost(path, remote))
		return rec.Code
	}

	const claim = "/api/v1/auth/claim"
	// POSITIVE CONTROL: the route is mounted, or "never 429" would pass on a 404.
	if code := serve(claim, "203.0.113.20:1000"); code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: %s is not mounted (404)", claim)
	}
	for i := 1; i < 3; i++ {
		if code := serve(claim, "203.0.113.20:1000"); code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited; want the first 3 to pass", i+1)
		}
	}
	if code := serve(claim, "203.0.113.20:1000"); code != http.StatusTooManyRequests {
		t.Errorf("4th credential POST from one address = %d; want 429", code)
	}
	if code := serve(claim, "203.0.113.21:1000"); code == http.StatusTooManyRequests {
		t.Errorf("another address = 429; each address has its own bucket")
	}
}

func TestResolveRateLimitConfig_CredentialDefault(t *testing.T) {
	cfg := resolveRateLimitConfig(func(string) string { return "" })
	if got := cfg.CredentialLimit; got.RequestsPerWindow != 120 || got.WindowDuration != time.Minute {
		t.Errorf("credential default = %d/%s; want 120/1m", got.RequestsPerWindow, got.WindowDuration)
	}
}
