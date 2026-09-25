package runtime

// OSS-SEC: POST /api/v1/auth/resend-verification sends mail on request and
// GET /api/v1/auth/verify-email burns a token on request; until this slice
// neither carried a limiter, so one client could flood an inbox. These tests
// drive the REAL assembled engine (api.NewOSSEngine) with the RateLimitConfig
// the runtime produces (resolveRateLimitConfig reading the env overrides),
// as TestNewOSSEngine_PasswordResetRateLimited does.
//
//   - resend is limited per client IP, and per target ADDRESS whatever the
//     client IP (the bucket key is a hash of the address);
//   - a known and an unknown address are answered and counted identically;
//   - verify-email is limited per client IP;
//   - the 429 is the other limiters' shape.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// verifyStubUsers knows one unverified user; every other address is unknown.
type verifyStubUsers struct{ known string }

func (u verifyStubUsers) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	if email == u.known {
		return []*domain.User{{ID: uuid.New(), OrganizationID: uuid.New(), Email: email}}, nil
	}
	return nil, nil
}

func (verifyStubUsers) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

func (verifyStubUsers) Update(context.Context, uuid.UUID, uuid.UUID, repository.UpdateUserOptions) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

// verifyStubRows accepts every new verification row.
type verifyStubRows struct {
	repository.EmailVerificationRepository
}

func (verifyStubRows) Create(context.Context, *domain.EmailVerification) error { return nil }

const verifyKnownAddress = "known@example.test"

func verifyEngine(t *testing.T) http.Handler {
	t.Helper()
	svc := service.NewEmailVerificationService(verifyStubUsers{known: verifyKnownAddress}, verifyStubRows{}, nil, nil,
		service.EmailVerificationServiceOptions{})
	return api.NewOSSEngine(api.OSSRouterDeps{
		EmailVerificationService: svc,
		RateLimitConfig:          resolveRateLimitConfig(nil), // nil → os.Getenv → the t.Setenv overrides
	})
}

func resend(e http.Handler, ip, email string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification",
		strings.NewReader(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":5555"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

const resendAccepted = `{"success":true,"message":"If this email is registered, a verification link has been sent."}`

func assertRateLimited(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s: status %d body %s; want 429 — the route is not limited", what, rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"message":"Rate limit exceeded. Try again later.","success":false}` || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("%s: 429 body %s Retry-After %q; want the other limiters' shape", what, got, rec.Header().Get("Retry-After"))
	}
}

// With no override the three classes carry their published defaults, so
// none of the limiters is a no-op in a default deployment.
func TestResolveRateLimitConfig_EmailVerificationDefaults(t *testing.T) {
	cfg := resolveRateLimitConfig(func(string) string { return "" })
	for name, got := range map[string]ratelimit.RateLimit{
		"EmailVerificationResendLimit 10/15m": cfg.EmailVerificationResendLimit,
		"EmailVerificationAddressLimit 3/1h":  cfg.EmailVerificationAddressLimit,
		"EmailVerifyLimit 30/15m":             cfg.EmailVerifyLimit,
	} {
		want := map[string]ratelimit.RateLimit{
			"EmailVerificationResendLimit 10/15m": {RequestsPerWindow: 10, WindowDuration: 15 * time.Minute},
			"EmailVerificationAddressLimit 3/1h":  {RequestsPerWindow: 3, WindowDuration: time.Hour},
			"EmailVerifyLimit 30/15m":             {RequestsPerWindow: 30, WindowDuration: 15 * time.Minute},
		}[name]
		if got != want {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

// Past the per-IP window, resend from one client answers 429, while the
// requests before it get the anti-enumeration 200.
func TestResendVerification_LimitedPerClientIP(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFICATION_RESEND_REQUESTS", "3")
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFICATION_ADDRESS_REQUESTS", "100")
	e := verifyEngine(t)
	for i := 1; i <= 3; i++ {
		rec := resend(e, "203.0.113.20", "someone-"+string(rune('a'+i))+"@example.test")
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != resendAccepted {
			t.Fatalf("resend %d: %d %s; want the uniform 200", i, rec.Code, rec.Body.String())
		}
	}
	assertRateLimited(t, "resend 4 from one IP", resend(e, "203.0.113.20", "someone-z@example.test"))
}

// One target address has its own budget, whatever the client IP: an inbox
// cannot be flooded from many addresses. A known and an unknown address
// get identical answers and are counted identically.
func TestResendVerification_LimitedPerTargetAddress(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFICATION_RESEND_REQUESTS", "100")
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFICATION_ADDRESS_REQUESTS", "2")
	e := verifyEngine(t)
	for _, addr := range []string{verifyKnownAddress, "unknown@example.test"} {
		for i := 1; i <= 2; i++ {
			rec := resend(e, "198.51.100."+string(rune('0'+i)), addr)
			if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != resendAccepted {
				t.Fatalf("%s resend %d: %d %s; want the uniform 200", addr, i, rec.Code, rec.Body.String())
			}
		}
		assertRateLimited(t, addr+" resend 3 from a third IP", resend(e, "198.51.100.9", addr))
	}
	// The address, not the IP, ran out: another address from the same IP is
	// still admitted.
	if rec := resend(e, "198.51.100.9", "fresh@example.test"); rec.Code != http.StatusOK {
		t.Fatalf("a fresh address from the same IP: %d; want 200", rec.Code)
	}
}

// Past the per-IP window, verify-email answers 429 instead of reaching the
// token check.
func TestVerifyEmail_LimitedPerClientIP(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_RATE_LIMIT_EMAIL_VERIFY_REQUESTS", "3")
	e := verifyEngine(t)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email", nil)
		req.RemoteAddr = "203.0.113.30:5555"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	for i := 1; i <= 3; i++ {
		if rec := get(); rec.Code != http.StatusBadRequest {
			t.Fatalf("verify %d without a token: %d %s; want 400 from the handler", i, rec.Code, rec.Body.String())
		}
	}
	assertRateLimited(t, "verify 4 from one IP", get())
}
