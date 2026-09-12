package api

// THE-UNLIMITED-REGENERATE / ROUTE-RATELIMIT-2. POST
// /api/v1/me/mfa/recovery-codes/regenerate proves itself with a six-digit
// TOTP matched over a ±1-step window and, until this slice, its group carried
// mw.RequireAuthenticated and nothing else — an authenticated caller could try
// codes at wire speed. RATE-TOKEN-1's check (internal/mw/rate_limit_test.go)
// proves the limiter MECHANISM on a synthetic /probe route; ROUTE-RATELIMIT-1
// proves the /oauth/token mount. Neither says anything about this route, and
// deleting the mount in router.go's mountAuthSessions leaves both green.
//
// This test is BEHAVIORAL through the REAL router: NewOSSEngine with a tiny
// configured MFARecoveryCodesRegenerateLimit, a stub bearer verifier that
// admits two subjects, and POSTs carrying a WRONG code. The wrong code is the
// point — every admitted request must reach the handler and be refused as
// 401 invalid_code (the guard's own 401 carries no such code), so the
// premise that traffic passes the guard and the limiter is observed, not
// assumed. Past the limit the router must answer 429; a SECOND subject on the
// SAME client IP must still be admitted (the bucket is per subject, not per
// IP); and with a zero-value RateLimitConfig the route must behave exactly as
// before — never 429.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/ratelimit"
)

// regenStubVerifier admits each configured bearer token as its principal and
// refuses every other token, so the guard behind it is exercised for real.
type regenStubVerifier struct {
	principals map[string]*domain.Principal
}

func (v regenStubVerifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	if p, ok := v.principals[token]; ok {
		return p, nil
	}
	return nil, errors.New("stub: unknown bearer token")
}

// regenStubUserRepo answers GetByID for the seeded MFA-enrolled users. Every
// other method is the embedded nil interface: the refused-proof path reaches
// only GetByID, and any other call would panic loudly rather than pass.
type regenStubUserRepo struct {
	repository.UserRepository
	users map[uuid.UUID]*domain.User
}

func (r *regenStubUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := r.users[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, errors.New("stub: no such user")
}

// The remaining seams are required non-nil by the constructors and never
// reached on this path.
type regenStubPendingRepo struct {
	repository.MFAPendingLoginSessionRepository
}
type regenStubSessionRepo struct{ repository.SessionRepository }
type regenIdentityCipher struct{}

func (regenIdentityCipher) Encrypt(s string) (string, error) { return s, nil }
func (regenIdentityCipher) Decrypt(s string) (string, error) { return s, nil }

type regenSubject struct {
	token string
	id    uuid.UUID
}

// newRegenEngine builds the PRODUCTION router with the regenerate route
// mounted (UserSessionService + MFAEnrollment wired) behind a bearer verifier
// that admits the returned subjects, under the given rate-limit config.
func newRegenEngine(t *testing.T, cfg ratelimit.RateLimitConfig, subjects ...string) (*gin.Engine, []regenSubject) {
	t.Helper()
	users := &regenStubUserRepo{users: map[uuid.UUID]*domain.User{}}
	principals := map[string]*domain.Principal{}
	out := make([]regenSubject, 0, len(subjects))
	for _, token := range subjects {
		id := uuid.New()
		secret := "JBSWY3DPEHPK3PXP" // any base32 seed; the posted code is wrong on purpose
		users.users[id] = &domain.User{
			ID:             id,
			OrganizationID: uuid.New(),
			Email:          token + "@example.com",
			Role:           domain.RoleOrgUser,
			AuthSource:     domain.AuthSourceLocal,
			EmailVerified:  true,
			MFAEnabled:     true,
			MFASecret:      &secret,
		}
		principals[token] = &domain.Principal{UserID: id, Sub: id.String(), Role: domain.RoleOrgUser}
		out = append(out, regenSubject{token: token, id: id})
	}
	mfa := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: regenStubPendingRepo{},
		Users:   users,
		Issuer:  "Identuum",
		Cipher:  regenIdentityCipher{},
	}, service.MFAEnrollmentServiceOptions{})
	sessions := service.NewUserSessionService(nil, regenStubSessionRepo{}, service.UserSessionServiceOptions{})
	engine := NewOSSEngine(OSSRouterDeps{
		DiscoveryConfig:    server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		TokenVerifier:      regenStubVerifier{principals: principals},
		UserSessionService: sessions,
		MFAEnrollment:      mfa,
		Audit:              &audit.Recorder{},
		RateLimitConfig:    cfg,
	})
	return engine, out
}

// postRegenerate posts a WRONG code as the given subject from ONE client IP
// and returns the status and body.
func postRegenerate(engine *gin.Engine, token string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/mfa/recovery-codes/regenerate",
		strings.NewReader(`{"code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "203.0.113.7:44444" // one stable client IP for EVERY subject
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// mustReachHandler is the non-emptiness premise: the request passed the guard
// AND the limiter and was refused by the HANDLER (401 invalid_code). The
// guard's own refusal is also a 401 but never carries invalid_code, and a 404
// means the route is not mounted at all.
func mustReachHandler(t *testing.T, i int, code int, body string) {
	t.Helper()
	switch {
	case code == http.StatusTooManyRequests:
		t.Fatalf("PREMISE broken: request %d already 429 — the window never admitted traffic", i)
	case code == http.StatusNotFound:
		t.Fatalf("PREMISE broken: /api/v1/me/mfa/recovery-codes/regenerate not mounted (404) — the pin has drifted off its target")
	case code != http.StatusUnauthorized || !strings.Contains(body, "invalid_code"):
		t.Fatalf("PREMISE broken: request %d answered %d body=%q; want 401 invalid_code from the handler (the wrong code must reach it through the guard)", i, code, body)
	}
}

// RULE: ROUTE-RATELIMIT-2
func TestMFARecoveryCodesRegenerateRoute_RealRouterEnforcesConfiguredLimitPerSubject(t *testing.T) {
	const limit = 3
	engine, subjects := newRegenEngine(t, ratelimit.RateLimitConfig{
		MFARecoveryCodesRegenerateLimit: ratelimit.RateLimit{RequestsPerWindow: limit, WindowDuration: time.Minute},
	}, "alice-token", "bob-token")
	alice, bob := subjects[0], subjects[1]

	// Under the limit the route answers exactly as before: the wrong code
	// reaches the handler and is refused 401 invalid_code.
	for i := 1; i <= limit; i++ {
		code, body := postRegenerate(engine, alice.token)
		mustReachHandler(t, i, code, body)
	}

	// Past the configured limit the REAL router must throttle this subject.
	over, body := postRegenerate(engine, alice.token)
	if over != http.StatusTooManyRequests {
		t.Fatalf("request %d exceeded MFARecoveryCodesRegenerateLimit=%d yet the production router answered %d body=%q, want 429 — the regenerate limiter is unmounted", limit+1, limit, over, body)
	}

	// The bucket is PER SUBJECT: a second subject on the SAME client IP is
	// still admitted after the first is throttled. A per-IP bucket would
	// answer 429 here.
	code, body := postRegenerate(engine, bob.token)
	if code == http.StatusTooManyRequests {
		t.Fatalf("second subject on the same IP answered 429 after the first subject exhausted its bucket — the limiter is keyed per IP, want per authenticated subject")
	}
	mustReachHandler(t, limit+2, code, body)
}

// The third direction of ROUTE-RATELIMIT-2 (the tag above binds the file):
// a zero-value config must leave the route exactly as it was.
func TestMFARecoveryCodesRegenerateRoute_ZeroValueConfigIsInert(t *testing.T) {
	engine, subjects := newRegenEngine(t, ratelimit.RateLimitConfig{}, "carol-token")
	carol := subjects[0]

	// Well past any default: with a zero-value config the limiter is the
	// documented no-op and every request behaves exactly as before.
	for i := 1; i <= 12; i++ {
		code, body := postRegenerate(engine, carol.token)
		if code == http.StatusTooManyRequests {
			t.Fatalf("request %d answered 429 under a zero-value RateLimitConfig — the limiter is not inert", i)
		}
		mustReachHandler(t, i, code, body)
	}
}
