package handlers

// The opt-in step status of the password step (F5, owner ruling 2026-10-01):
// a correct password whose next step is MFA answers 401 by default and, only
// when the request carries `X-Identuum-Login-Step-Status: 200`, answers 200
// with the same body — no session, no cookie, no token. Every other answer is
// unchanged with or without the header.
//
// Password values are sentinel placeholders and never echoed by an assertion.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func loginStepEngine(t *testing.T) *gin.Engine {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXP" // arbitrary base32 — never a real secret
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["enrolled@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "enrolled@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleSiteAdmin,
			MFAEnabled:    true,
			MFASecret:     &secret,
		}}
		u.byEmail["unenrolled@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "unenrolled@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleSiteAdmin,
		}}
	})
	return r
}

func loginStep(r *gin.Engine, email, password, stepStatus string) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	if stepStatus != "" {
		req.Header.Set(LoginStepStatusHeader, stepStatus)
	}
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertNoCredentialMaterial(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("Set-Cookie present on a next-step answer (%d cookie(s))", len(cookies))
	}
	for _, banned := range []string{`"access_token"`, `"refresh_token"`, `"token_type"`} {
		if strings.Contains(w.Body.String(), banned) {
			t.Fatalf("body carries %s on a next-step answer", banned)
		}
	}
}

func TestLoginStepStatus_HeaderName(t *testing.T) {
	if LoginStepStatusHeader != "X-Identuum-Login-Step-Status" {
		t.Fatalf("LoginStepStatusHeader = %q", LoginStepStatusHeader)
	}
}

func TestLoginStepStatus_MFARequired(t *testing.T) {
	r := loginStepEngine(t)
	// Today's answer, pinned byte for byte (no pending store in this engine,
	// so no session_id).
	const want = `{"error":"mfa_required","mfa_enrollment_required":false,"mfa_required":true}`
	def := loginStep(r, "enrolled@example.invalid", "correct", "")
	if def.Code != http.StatusUnauthorized || def.Body.String() != want {
		t.Fatalf("default: status %d body %q, want 401 %q", def.Code, def.Body.String(), want)
	}
	assertNoCredentialMaterial(t, def)
	opt := loginStep(r, "enrolled@example.invalid", "correct", "200")
	if opt.Code != http.StatusOK {
		t.Fatalf("opt-in: status %d, want 200", opt.Code)
	}
	if opt.Body.String() != def.Body.String() {
		t.Fatalf("opt-in body %q differs from the default body %q", opt.Body.String(), def.Body.String())
	}
	assertNoCredentialMaterial(t, opt)
}

func TestLoginStepStatus_MFAEnrollmentRequired(t *testing.T) {
	r := loginStepEngine(t)
	const want = `{"error":"mfa_enrollment_required","mfa_enrollment_required":true,"mfa_required":true}`
	def := loginStep(r, "unenrolled@example.invalid", "correct", "")
	if def.Code != http.StatusUnauthorized || def.Body.String() != want {
		t.Fatalf("default: status %d body %q, want 401 %q", def.Code, def.Body.String(), want)
	}
	opt := loginStep(r, "unenrolled@example.invalid", "correct", "200")
	if opt.Code != http.StatusOK || opt.Body.String() != want {
		t.Fatalf("opt-in: status %d body %q, want 200 %q", opt.Code, opt.Body.String(), want)
	}
	assertNoCredentialMaterial(t, opt)
}

func TestLoginStepStatus_OnlyTheExactValueOptsIn(t *testing.T) {
	r := loginStepEngine(t)
	for _, v := range []string{"1", "true", "ok", " 200", "201"} {
		if w := loginStep(r, "enrolled@example.invalid", "correct", v); w.Code != http.StatusUnauthorized {
			t.Fatalf("header value %q: status %d, want the default 401", v, w.Code)
		}
	}
}

// pendingRegistration answers the self-registration gate: held is a
// self-registrant waiting for approval (D-021); everyone else is not
// self-registered.
type pendingRegistration struct{ held uuid.UUID }

func (p pendingRegistration) UserState(_ context.Context, id uuid.UUID) (string, bool, error) {
	if id == p.held {
		return domain.RegistrationStatePendingApproval, false, nil
	}
	return "", false, nil
}

// OSS-TIDY-2: a pending self-registrant's correct password is an expected
// state the console shows ("waiting for approval"), so under the exact opt-in
// it answers 200 with the byte-identical body — still no session, cookie or
// token. Without it, or with any other value, the default 403 stands.
func TestLoginStepStatus_RegistrationPending(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	held := uuid.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{
		"held@example.invalid": {{
			ID:           held,
			Email:        "held@example.invalid",
			PasswordHash: hashPasswordForHandlers(t, "correct"),
			Role:         domain.RoleOrgUser,
		}},
	}}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{Replay: testReplayGuardForHandlers()})
	login := service.NewLocalLoginService(nil, users, sessions, mfa).WithRegistrationStates(pendingRegistration{held: held})
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{LocalLogin: login, UserSession: sessions, Audit: &audit.Recorder{}})

	const want = `{"error":"registration_pending"}`
	def := loginStep(r, "held@example.invalid", "correct", "")
	if def.Code != http.StatusForbidden || def.Body.String() != want {
		t.Fatalf("default: status %d body %q, want 403 %q", def.Code, def.Body.String(), want)
	}
	assertNoCredentialMaterial(t, def)
	opt := loginStep(r, "held@example.invalid", "correct", LoginStepStatusOK)
	if opt.Code != http.StatusOK || opt.Body.String() != want {
		t.Fatalf("opt-in: status %d body %q, want 200 %q", opt.Code, opt.Body.String(), want)
	}
	assertNoCredentialMaterial(t, opt)
	for _, v := range []string{"1", "true", " 200", "201"} {
		if w := loginStep(r, "held@example.invalid", "correct", v); w.Code != http.StatusForbidden {
			t.Fatalf("header value %q: status %d, want the default 403", v, w.Code)
		}
	}
	// A wrong password of the same account stays the default refusal.
	if w := loginStep(r, "held@example.invalid", "wrong", LoginStepStatusOK); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password under the opt-in: status %d, want 401", w.Code)
	}
}

func TestLoginStepStatus_WrongPasswordUnchanged(t *testing.T) {
	r := loginStepEngine(t)
	const want = `{"error":"invalid_credentials"}`
	for _, v := range []string{"", "200"} {
		w := loginStep(r, "enrolled@example.invalid", "wrong", v)
		if w.Code != http.StatusUnauthorized || w.Body.String() != want {
			t.Fatalf("wrong password, header %q: status %d body %q, want 401 %q", v, w.Code, w.Body.String(), want)
		}
		assertNoCredentialMaterial(t, w)
	}
}
