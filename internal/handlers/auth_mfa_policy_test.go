package handlers

// Handler-layer tests pinning the wire contract emitted on the MFA
// enforcement paths added by slice
// agent-a-identuum-idp-oss-mfa-policy-enforcement:
//
//   - 401 {"error":"mfa_enrollment_required"} when MFA is required by
//     role/org policy but the user has not enrolled.
//   - 401 {"error":"mfa_required"} when an enrolled admin omits the
//     TOTP code.
//   - NO Set-Cookie headers on any of the above paths.
//
// Test discipline:
//   - Password values are sentinel placeholders ("correct" / "wrong")
//     — never real credentials — and the assertion code never echoes
//     them back into a failure message.
//   - Set-Cookie assertions are structural (absence-of-cookie checks).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func TestLoginRoute_SiteAdminWithoutMFAReturnsEnrollmentRequiredAndNoCookies(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["admin@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "admin@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleSiteAdmin,
		}}
	})
	body := strings.NewReader(`{"email":"admin@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var respBody map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &respBody)
	if respBody["error"] != "mfa_enrollment_required" {
		t.Fatalf("error: want mfa_enrollment_required, got %v", respBody["error"])
	}
	// Defence in depth: response body MUST NOT carry token / session
	// material on this path.
	for _, banned := range []string{"access_token", "refresh_token", "session_id", "user_id"} {
		if _, present := respBody[banned]; present {
			t.Fatalf("response leaked %q on mfa_enrollment_required path", banned)
		}
	}
	// No cookies must be set on the enrolment-required path.
	if cookies := w.Result().Cookies(); len(cookies) != 0 {
		names := make([]string, 0, len(cookies))
		for _, c := range cookies {
			names = append(names, c.Name)
		}
		t.Fatalf("Set-Cookie present on mfa_enrollment_required path: %v", names)
	}
}

func TestLoginRoute_OrgAdminWithoutMFAReturnsEnrollmentRequiredAndNoCookies(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["orgadmin@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "orgadmin@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleOrgAdmin,
		}}
	})
	body := strings.NewReader(`{"email":"orgadmin@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"mfa_enrollment_required"`) {
		t.Fatalf("body: want mfa_enrollment_required, got %q", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("Set-Cookie must be absent on mfa_enrollment_required path")
	}
}

func TestLoginRoute_OrgUserRequiredPolicyWithoutMFAReturnsEnrollmentRequired(t *testing.T) {
	policy := "required"
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["user@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "user@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleOrgUser,
			MFAPolicy:     &policy,
		}}
	})
	body := strings.NewReader(`{"email":"user@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"mfa_enrollment_required"`) {
		t.Fatalf("body: want mfa_enrollment_required, got %q", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("Set-Cookie must be absent on mfa_enrollment_required path")
	}
}

func TestLoginRoute_OrgUserOptionalPolicyNoMFAStillSucceedsWithCookies(t *testing.T) {
	// Preserved legacy behaviour. The org_user IS NOT an admin and the
	// org policy IS optional, so password-only login completes and
	// cookies are issued.
	policy := "optional"
	r := newAuthEngineWithToken(t, func(u *inMemoryUserLookupForHandlers, byID *inMemoryUserByIDLookup) {
		uid := uuid.New()
		row := &domain.User{
			ID:            uid,
			Email:         "user@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleOrgUser,
			MFAPolicy:     &policy,
		}
		u.byEmail["user@example.invalid"] = []*domain.User{row}
		byID.byID[uid] = row
	})
	body := strings.NewReader(`{"email":"user@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	hasAccess := false
	for _, c := range cookies {
		if c.Name == "access_token" {
			hasAccess = true
		}
	}
	if !hasAccess {
		t.Fatal("optional-policy org_user login must set access_token cookie")
	}
}

func TestLoginRoute_AdminWithMFAEnabledMissingCodeReturnsMFARequiredNoCookies(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" // arbitrary base32 — never the real secret
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["admin@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "admin@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleSiteAdmin,
			MFAEnabled:    true,
			MFASecret:     &secret,
		}}
	})
	body := strings.NewReader(`{"email":"admin@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"mfa_required"`) {
		t.Fatalf("body: want mfa_required, got %q", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("Set-Cookie must be absent on mfa_required path")
	}
}

func TestLoginRoute_WrongPasswordAdminStillReturnsInvalidCredentials(t *testing.T) {
	// MFA-enforcement decisions MUST NOT leak whether MFA is required
	// for an arbitrary email — wrong password runs the same wire path
	// regardless of role.
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["admin@example.invalid"] = []*domain.User{{
			ID:            uuid.New(),
			Email:         "admin@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleSiteAdmin,
		}}
	})
	body := strings.NewReader(`{"email":"admin@example.invalid","password":"wrong"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"invalid_credentials"`) {
		t.Fatalf("body: want invalid_credentials, got %q", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("Set-Cookie must be absent on invalid_credentials path")
	}
}
