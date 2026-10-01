package handlers

// The opt-in step status of the password step (F5, owner ruling 2026-10-01):
// a correct password whose next step is MFA answers 401 by default and, only
// when the request carries `X-Identuum-Login-Step-Status: 200`, answers 200
// with the same body — no session, no cookie, no token. Every other answer is
// unchanged with or without the header.
//
// Password values are sentinel placeholders and never echoed by an assertion.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
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
