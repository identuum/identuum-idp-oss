package handlers

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
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// scriptedLoginAttemptRepo returns a fixed count/err so a test can drive
// either the genuine-lockout path (count >= threshold, err nil) or the
// fail-CLOSED path (err non-nil). The fixed count drives the ACCOUNT
// counter; the IP distinct-account counter returns 0 (under threshold), so
// the genuine-lockout path is the account lock (P2-10).
type scriptedLoginAttemptRepo struct {
	count int
	err   error
}

func (r scriptedLoginAttemptRepo) Insert(context.Context, *domain.LoginAttempt) error { return nil }
func (r scriptedLoginAttemptRepo) CountAccountFailuresSince(context.Context, string, string, string, time.Time) (int, error) {
	return r.count, r.err
}
func (r scriptedLoginAttemptRepo) CountDistinctAccountsFromIPSince(context.Context, string, string, time.Time) (int, error) {
	return 0, r.err
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
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
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

// TestLoginRoute_GenuineLockoutIsInvalidCredentials proves the
// no-enumeration posture is preserved: a genuine 5-failure lockout
// (backend healthy, count >= threshold) returns the SAME generic 401
// invalid_credentials as a wrong password — NOT the 503. The
// 503-vs-401 split therefore tracks backend state only, never lockout
// state.
// RULE: LOCKOUT-1
func TestLoginRoute_GenuineLockoutIsInvalidCredentials(t *testing.T) {
	seed := func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash: hashPasswordForHandlers(t, "correct"), EmailVerified: true,
		}}
	}
	// count=5 >= threshold(5), err=nil → genuine lockout.
	r := newAuthEngineWithRisk(t, seed, scriptedLoginAttemptRepo{count: 5})

	// Even with the CORRECT password, a locked-out caller gets the
	// generic invalid_credentials 401 (indistinguishable from wrong
	// password), and never a 503.
	w := postLogin(t, r, "alice@example.com", "correct")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_credentials") {
		t.Fatalf("body = %q, want invalid_credentials", w.Body.String())
	}
	if w.Code == http.StatusServiceUnavailable {
		t.Fatal("a genuine lockout must NOT surface as 503 (that would reveal lockout state)")
	}
}
