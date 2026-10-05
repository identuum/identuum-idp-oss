package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// scriptedLoginAttemptRepo returns a fixed count/err so a test can drive
// either the genuine-lockout path (count >= threshold, err nil) or the
// fail-CLOSED path (err non-nil). The fixed count drives the ACCOUNT
// counter; the IP distinct-account counter returns 0 (under threshold), so
// the genuine-lockout path is the account lock (P2-10).
type scriptedLoginAttemptRepo struct {
	count int
	anyIP int // account-wide failures from any address (the slow-down)
	err   error
}

func (r scriptedLoginAttemptRepo) Insert(context.Context, *domain.LoginAttempt) error { return nil }

// CountAccountFailuresSince reports the scripted count with the oldest
// failure just recorded.
func (r scriptedLoginAttemptRepo) CountAccountFailuresSince(context.Context, string, string, string, time.Time) (int, time.Time, error) {
	return r.count, time.Now(), r.err
}
func (r scriptedLoginAttemptRepo) CountDistinctAccountsFromIPSince(context.Context, string, string, time.Time) (int, time.Time, error) {
	return 0, time.Time{}, r.err
}

// AccountFailuresAnyIPSince reports throttled failures as of now: the
// scripted count with the newest failure just recorded.
func (r scriptedLoginAttemptRepo) AccountFailuresAnyIPSince(context.Context, string, string, time.Time) (int, time.Time, error) {
	return r.anyIP, time.Now(), r.err
}
func (r scriptedLoginAttemptRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

var _ repository.LoginAttemptRepository = scriptedLoginAttemptRepo{}

// newAuthEngineWithRisk mirrors newAuthEngine but wires a LoginRiskService
// backed by the supplied repo so the P1-4 fail-closed / lockout wire
// mappings can be exercised end to end.
func newAuthEngineWithRisk(t *testing.T, seed func(*inMemoryUserLookupForHandlers), risk repository.LoginAttemptRepository) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	if seed != nil {
		seed(users)
	}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{Replay: testReplayGuardForHandlers()})
	riskSvc := service.NewLoginRiskService(nil, risk, service.LoginRiskServiceOptions{Threshold: 5, Window: time.Minute})
	login := service.NewLocalLoginService(nil, users, sessions, mfa).WithLoginRiskService(riskSvc)
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		LocalLogin:  login,
		UserSession: sessions,
		Audit:       &audit.Recorder{},
	})
	return r
}

func postLogin(t *testing.T, r *gin.Engine, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestLoginRoute_RiskBackendUnavailableIs503 pins the fail-CLOSED wire
// mapping: when the risk backend errors, the login is refused with 503
// "temporarily_unavailable" — never a silent success and never
// invalid_credentials. It fires identically for a KNOWN and an UNKNOWN
// account, proving the 503 reveals ONLY backend state, never account
// state. TEETH: revert Check to `return nil` and this returns 200/401,
// failing the test.
func TestLoginRoute_RiskBackendUnavailableIs503(t *testing.T) {
	seed := func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
		}}
	}
	r := newAuthEngineWithRisk(t, seed, scriptedLoginAttemptRepo{err: errors.New("store outage")})

	cases := []struct{ name, email, password string }{
		{"known account, correct password", "alice@example.com", "correct"},
		{"known account, wrong password", "alice@example.com", "wrong"},
		{"unknown account", "nobody@example.com", "whatever"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postLogin(t, r, tc.email, tc.password)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body=%q", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "temporarily_unavailable") {
				t.Fatalf("body = %q, want temporarily_unavailable", w.Body.String())
			}
			if strings.Contains(w.Body.String(), "invalid_credentials") {
				t.Fatalf("503 body must NOT reveal credential/account state: %q", w.Body.String())
			}
		})
	}
}

// TestLoginRoute_AHeldBoundSaysToWait pins the answer while a failure bound
// holds (backend healthy, count >= threshold): 429 login_throttled with
// Retry-After, the answer the account-wide slow-down gives (FUNC-M2) — never
// 401 invalid_credentials, which told a correct password it was wrong, and
// never the 503 of an unavailable backend. A known and an unknown account get
// the same answer, so it enumerates nothing.
// RULE: LOCKOUT-1
func TestLoginRoute_AHeldBoundSaysToWait(t *testing.T) {
	seed := func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
		}}
	}
	// count=5 >= threshold(5), err=nil → the pair bound holds; its oldest
	// failure was just recorded, so the wait is the 1-minute window.
	r := newAuthEngineWithRisk(t, seed, scriptedLoginAttemptRepo{count: 5})

	for _, email := range []string{"alice@example.com", "nobody@example.com"} {
		w := postLogin(t, r, email, "correct")
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"login_throttled"`) {
			t.Fatalf("%s: status = %d body = %q, want 429 login_throttled", email, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "invalid_credentials") {
			t.Fatalf("%s: a held bound answered invalid_credentials: %q", email, w.Body.String())
		}
		secs, err := strconv.Atoi(w.Header().Get("Retry-After"))
		if err != nil || secs < 1 || secs > 60 {
			t.Errorf("%s: Retry-After = %q, want 1..60 seconds", email, w.Header().Get("Retry-After"))
		}
	}
}
