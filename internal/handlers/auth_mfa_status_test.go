package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// statusReq is a one-liner GET helper mirroring recoveryReq from
// the regenerate test file, so the status tests can reuse the
// shared recoveryTestEngine + recoveryStubUserRepo + audit
// recorder without re-stating the wiring fixture.
func statusReq(t *testing.T, eng recoveryTestEngine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/mfa/status", nil)
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

func seedStatusUser(eng recoveryTestEngine, id uuid.UUID, mfaEnabled bool, codeCount int) *domain.User {
	codes := make([]string, 0, codeCount)
	for i := 0; i < codeCount; i++ {
		codes = append(codes, "CODE-"+uuid.NewString())
	}
	secret := "PRESERVED-SECRET-LITERAL-status"
	u := &domain.User{
		ID:               id,
		OrganizationID:   uuid.New(),
		Email:            "self@example.com",
		Role:             domain.RoleOrgUser,
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		MFAEnabled:       mfaEnabled,
		MFASecret:        &secret,
		MFARecoveryCodes: codes,
	}
	eng.userRepo.byID[id] = u
	return u
}

func TestMFAStatus_Unauthenticated401(t *testing.T) {
	eng := newRecoveryEngine(t, nil)
	w := statusReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestMFAStatus_NotEnrolledReportsZero(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	// Seed with MFAEnabled=false and an empty codes slice.
	seedStatusUser(eng, uid, false /* MFAEnabled */, 0)
	w := statusReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	var resp struct {
		MFAEnabled                  bool `json:"mfa_enabled"`
		RecoveryCodesRemainingCount int  `json:"recovery_codes_remaining_count"`
		TOTPEnrolled                bool `json:"totp_enrolled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.MFAEnabled {
		t.Errorf("mfa_enabled = true on un-enrolled user")
	}
	if resp.RecoveryCodesRemainingCount != 0 {
		t.Errorf("recovery_codes_remaining_count = %d; want 0", resp.RecoveryCodesRemainingCount)
	}
	if resp.TOTPEnrolled {
		t.Errorf("totp_enrolled = true on un-enrolled user")
	}
	// Repo Update must never fire on a status read.
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times on read-only status; want 0", eng.userRepo.calls)
	}
}

func TestMFAStatus_EnrolledReportsCounts(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedStatusUser(eng, uid, true /* MFAEnabled */, 7 /* codeCount */)
	w := statusReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", w.Code, w.Body.String())
	}
	var resp struct {
		MFAEnabled                  bool `json:"mfa_enabled"`
		RecoveryCodesRemainingCount int  `json:"recovery_codes_remaining_count"`
		TOTPEnrolled                bool `json:"totp_enrolled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.MFAEnabled {
		t.Errorf("mfa_enabled = false")
	}
	if resp.RecoveryCodesRemainingCount != 7 {
		t.Errorf("recovery_codes_remaining_count = %d; want 7", resp.RecoveryCodesRemainingCount)
	}
	if !resp.TOTPEnrolled {
		t.Errorf("totp_enrolled = false")
	}
}

// TestMFAStatus_DoesNotLeakSecretOrCodeMaterial pins the no-leak
// contract: a seeded TOTP secret literal AND every stored recovery
// code literal must be absent from the response body, headers, and
// JSON field names.
func TestMFAStatus_DoesNotLeakSecretOrCodeMaterial(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	user := seedStatusUser(eng, uid, true, 3)
	w := statusReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "PRESERVED-SECRET-LITERAL-status") {
		t.Errorf("response leaked MFA secret: %q", body)
	}
	for _, c := range user.MFARecoveryCodes {
		if strings.Contains(body, c) {
			t.Errorf("response leaked recovery code %q: %q", c, body)
		}
	}
	// Forbid sensitive field names. recovery_codes_remaining_count
	// legitimately contains the substring "recovery_codes" so we
	// match the leaky JSON pattern (`"recovery_codes":[`) instead
	// of the bare substring.
	for _, fieldName := range []string{
		"mfa_secret",
		"otpauth",
		"password_hash",
		"access_token",
		"refresh_token",
		"session_id",
	} {
		if strings.Contains(body, fieldName) {
			t.Errorf("response leaked sensitive field name %q: %q", fieldName, body)
		}
	}
	// The codes-as-array leak shape — only the count is allowed
	// on this wire.
	if strings.Contains(body, `"recovery_codes":[`) {
		t.Errorf("response leaked recovery_codes array: %q", body)
	}
}

func TestMFAStatus_OtherUserStateNotExposedOrMutated(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedStatusUser(eng, uid, true, 2)
	otherSecret := "OTHER-SECRET-LITERAL"
	otherCodes := []string{"OTHER-A", "OTHER-B", "OTHER-C", "OTHER-D", "OTHER-E"}
	eng.userRepo.byID[other] = &domain.User{
		ID:               other,
		OrganizationID:   uuid.New(),
		Email:            "other@example.com",
		MFAEnabled:       true,
		MFASecret:        &otherSecret,
		MFARecoveryCodes: append([]string(nil), otherCodes...),
	}
	w := statusReq(t, eng)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Other user's state MUST NOT leak into the response.
	if strings.Contains(body, otherSecret) {
		t.Errorf("response leaked OTHER user's MFA secret: %q", body)
	}
	for _, c := range otherCodes {
		if strings.Contains(body, c) {
			t.Errorf("response leaked OTHER user's recovery code: %q", body)
		}
	}
	// Status returns the principal's counts (2 codes), not the
	// other user's count (5).
	var resp struct {
		RecoveryCodesRemainingCount int `json:"recovery_codes_remaining_count"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RecoveryCodesRemainingCount != 2 {
		t.Errorf("recovery_codes_remaining_count = %d; want 2 (principal's, not other's)", resp.RecoveryCodesRemainingCount)
	}
	// Other user row is byte-identical after the call.
	stored := eng.userRepo.byID[other]
	if !stored.MFAEnabled {
		t.Error("other user MFAEnabled mutated by status read")
	}
	if stored.MFASecret == nil || *stored.MFASecret != otherSecret {
		t.Errorf("other user MFASecret mutated: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != len(otherCodes) {
		t.Errorf("other user code count changed: %d → %d", len(otherCodes), len(stored.MFARecoveryCodes))
	}
}

func TestMFAStatus_BannedPrincipalRejected(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	u := seedStatusUser(eng, uid, true, 3)
	u.Banned = true
	eng.userRepo.byID[uid] = u
	w := statusReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (banned)", w.Code)
	}
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times on banned read; want 0", eng.userRepo.calls)
	}
}

func TestMFAStatus_DeletedPrincipalRejected(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	u := seedStatusUser(eng, uid, true, 3)
	now := time.Now().UTC()
	u.DeletedAt = &now
	eng.userRepo.byID[uid] = u
	w := statusReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (deleted)", w.Code)
	}
}

func TestMFAStatus_StalePrincipalRejected(t *testing.T) {
	// Principal references a UUID that has no user row; the
	// service collapses this to ErrMFAEnrollmentInvalid and the
	// handler maps it to 401.
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgUser})
	w := statusReq(t, eng)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (stale principal)", w.Code)
	}
	if eng.userRepo.calls != 0 {
		t.Errorf("repo Update called %d times on stale principal; want 0", eng.userRepo.calls)
	}
}

// TestMFAStatus_RouteIsReadOnly pins that the status endpoint is
// GET-only — any other verb returns 404 from the gin mux (no
// duplicate POST/PUT/etc routes).
func TestMFAStatus_RouteIsReadOnly(t *testing.T) {
	uid := uuid.New()
	eng := newRecoveryEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedStatusUser(eng, uid, true, 1)
	// POSITIVE CONTROL — the route must EXIST, or the method fence below passes
	// against an unmounted path: a 404 to every verb satisfies "not 200" just as
	// well as a correct method rejection does.
	{
		ctlReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/mfa/status", nil)
		ctlW := httptest.NewRecorder()
		eng.r.ServeHTTP(ctlW, ctlReq)
		if ctlW.Code == http.StatusNotFound {
			t.Fatalf("CONTROL FAILED: GET /api/v1/me/mfa/status is not mounted (404); the method fence " +
				"below would pass against a route that does not exist")
		}
	}

	for _, verb := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(verb, "/api/v1/me/mfa/status", nil)
		w := httptest.NewRecorder()
		eng.r.ServeHTTP(w, req)
		// Gin returns 404 (not 405) by default when a path is
		// registered for a different verb. We accept either as
		// long as the response isn't 200 — the contract is "this
		// endpoint is GET-only".
		if w.Code == http.StatusOK {
			t.Errorf("%s /api/v1/me/mfa/status returned 200; expected non-200 (route is GET-only)", verb)
		}
	}
}
