package runtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// resetRequest builds a POST /api/v1/auth/password/reset-request with a
// malformed body so the handler returns its uniform 200 WITHOUT invoking
// the PasswordResetService — isolating the rate limiter.
func resetRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset-request", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:5555" // fixed source IP → one per-IP bucket
	return req
}

// TestNewOSSEngine_PasswordResetRateLimited drives the REAL assembled engine
// (api.NewOSSEngine) with the RateLimitConfig the runtime now produces and
// asserts an end-to-end 429 once the per-IP window is exhausted. This is the
// guard against F2 (rate limiting a runtime no-op). It FAILS against the
// pre-wiring code (zero-value RateLimitConfig → no 429 — see
// TestNewOSSEngine_ZeroRateLimitConfig_IsNoop) and PASSES once buildDeps
// populates the config via resolveRateLimitConfig.
func TestNewOSSEngine_PasswordResetRateLimited(t *testing.T) {
	// Tighten the reset limit via the real env path so the test is fast and
	// simultaneously exercises env-overridability.
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_PASSWORD_RESET_REQUESTS", "3")

	deps := api.OSSRouterDeps{
		PasswordResetService: service.NewPasswordResetService(service.PasswordResetServiceConfig{}),
		RateLimitConfig:      resolveRateLimitConfig(nil), // nil → os.Getenv → reads the env above
	}
	e := api.NewOSSEngine(deps)

	const limit = 3
	for i := 0; i < limit; i++ {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, resetRequest())
		if rec.Code != http.StatusOK {
			t.Fatalf("reset request %d: status = %d, want 200 (under limit)", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, resetRequest())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("reset request %d: status = %d, want 429 (end-to-end through NewOSSEngine)", limit+1, rec.Code)
	}
}

// TestNewOSSEngine_ZeroRateLimitConfig_IsNoop documents the pre-wiring bug
// (F2): with a zero-value RateLimitConfig — exactly what buildDeps produced
// before this slice — the assembled engine applies NO limiting, so requests
// far past any window all pass. This is why the guard test above failed
// against current code.
func TestNewOSSEngine_ZeroRateLimitConfig_IsNoop(t *testing.T) {
	deps := api.OSSRouterDeps{
		PasswordResetService: service.NewPasswordResetService(service.PasswordResetServiceConfig{}),
		RateLimitConfig:      ratelimit.RateLimitConfig{}, // zero == pre-wiring buildDeps
	}
	e := api.NewOSSEngine(deps)

	// POSITIVE CONTROL — the route must EXIST. "never 429" is satisfied by an
	// unmounted path answering 404 six times, which would report a working
	// no-op rate limiter on an engine serving nothing.
	ctl := httptest.NewRecorder()
	e.ServeHTTP(ctl, resetRequest())
	if ctl.Code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: the reset route is not mounted (404) — the no-limit " +
			"assertions below would pass against an engine that serves nothing")
	}

	for i := 0; i < 6; i++ {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, resetRequest())
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("zero-config engine limited at request %d — expected NO limiting (noop)", i+1)
		}
	}
}

// (d) TestResolveRateLimitConfig_Defaults pins the safe per-class defaults the
// shipped runtime applies when no env override is set.
func TestResolveRateLimitConfig_Defaults(t *testing.T) {
	cfg := resolveRateLimitConfig(func(string) string { return "" }) // no env

	cases := []struct {
		name   string
		got    ratelimit.RateLimit
		req    int
		window time.Duration
	}{
		{"login", cfg.LoginLimit, 5, time.Minute},
		{"register", cfg.RegisterLimit, 10, time.Hour},
		{"token", cfg.TokenLimit, 120, time.Minute},
		{"introspection", cfg.IntrospectionLimit, 600, time.Minute},
		{"revocation", cfg.RevocationLimit, 120, time.Minute},
		{"password-reset", cfg.PasswordResetLimit, 10, 15 * time.Minute},
	}
	for _, c := range cases {
		if c.got.RequestsPerWindow != c.req || c.got.WindowDuration != c.window {
			t.Errorf("%s default = %d/%s, want %d/%s", c.name, c.got.RequestsPerWindow, c.got.WindowDuration, c.req, c.window)
		}
		if c.got.RequestsPerWindow < 1 {
			t.Errorf("%s default RequestsPerWindow < 1 → would be a noop", c.name)
		}
	}
}

// (d) TestResolveRateLimitConfig_EnvOverride proves the IDENTUUM_IDP_RATE_LIMIT_*
// env vars drive the thresholds; an invalid/non-positive override keeps the
// safe default (never silently disables a limit).
func TestResolveRateLimitConfig_EnvOverride(t *testing.T) {
	env := map[string]string{
		"IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS":         "42",
		"IDENTUUM_IDP_RATE_LIMIT_LOGIN_WINDOW":           "30s",
		"IDENTUUM_IDP_RATE_LIMIT_TOKEN_REQUESTS":         "0",       // non-positive → ignored
		"IDENTUUM_IDP_RATE_LIMIT_INTROSPECTION_REQUESTS": "garbage", // invalid → ignored
	}
	cfg := resolveRateLimitConfig(func(k string) string { return env[k] })

	if cfg.LoginLimit.RequestsPerWindow != 42 || cfg.LoginLimit.WindowDuration != 30*time.Second {
		t.Errorf("login override = %d/%s, want 42/30s", cfg.LoginLimit.RequestsPerWindow, cfg.LoginLimit.WindowDuration)
	}
	if cfg.TokenLimit.RequestsPerWindow != 120 {
		t.Errorf("token with non-positive override = %d, want default 120 (override ignored)", cfg.TokenLimit.RequestsPerWindow)
	}
	if cfg.IntrospectionLimit.RequestsPerWindow != 600 {
		t.Errorf("introspection with invalid override = %d, want default 600 (override ignored)", cfg.IntrospectionLimit.RequestsPerWindow)
	}
}

// TestStart_PasswordResetRateLimited_EndToEnd is the durable end-to-end guard:
// it starts the FULL runtime (New + Start → buildDeps → NewOSSEngine) against a
// real Postgres and hammers the live reset endpoint, asserting a 429 once the
// (env-tightened) window is exhausted. Because it flows through buildDeps, it
// fails if buildDeps ever stops populating RateLimitConfig (the F2 regression).
// DB-gated: skips without IDENTUUM_IDP_TEST_DATABASE_URL (runs under verify-oss).
func TestStart_PasswordResetRateLimited_EndToEnd(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	// A-2a: opt out of the single-replica instance lease — this test starts
	// a full runtime to exercise rate limiting, not the lease, and must not
	// contend with parallel DB-backed runtime tests on one Postgres.
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_PASSWORD_RESET_REQUESTS", "3")

	rt, err := New(Config{
		Addr:      "127.0.0.1:0",
		Issuer:    "http://127.0.0.1:7113",
		JWKSDBURL: dbURL,
		DataDir:   t.TempDir(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	}()

	url := "http://" + rt.Addr() + "/api/v1/auth/password/reset-request"
	post := func() int {
		resp, err := http.Post(url, "application/json", strings.NewReader("not-json"))
		if err != nil {
			t.Fatalf("POST reset-request: %v", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	for i := 0; i < 3; i++ {
		if code := post(); code != http.StatusOK {
			t.Fatalf("live reset request %d: status = %d, want 200", i+1, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("live reset request 4: status = %d, want 429 (buildDeps must wire RateLimitConfig)", code)
	}
}
