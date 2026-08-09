package handlers

import (
	"bytes"
	"encoding/json"
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
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// disableTestEngine wires the smallest deps needed to mount POST
// /api/v1/me/mfa/disable. Reuses the same recoveryStubUserRepo /
// recoveryPendingRepoStub stubs defined in
// auth_mfa_recovery_codes_test.go so the disable tests do not
// duplicate the UserRepository surface.
type disableTestEngine struct {
	r              *gin.Engine
	userRepo       *recoveryStubUserRepo
	rec            *audit.Recorder
	sessionRevoker *service.RecorderSessionRevoker
	refreshRevoker *service.RecorderRefreshTokenRevoker
}

func newDisableEngine(t *testing.T, principal *domain.Principal) disableTestEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newRecoveryStubUserRepo()
	mfaSvc := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: recoveryPendingRepoStub{},
		Users:   userRepo,
		Issuer:  "Identuum",
		Cipher:  identityMFACipher{},
	}, service.MFAEnrollmentServiceOptions{})
	rec := &audit.Recorder{}
	sessionRevoker := &service.RecorderSessionRevoker{}
	refreshRevoker := &service.RecorderRefreshTokenRevoker{}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		MFAEnrollment:       mfaSvc,
		SessionRevoker:      sessionRevoker,
		RefreshTokenRevoker: refreshRevoker,
		Audit:               rec,
	})
	return disableTestEngine{r: r, userRepo: userRepo, rec: rec, sessionRevoker: sessionRevoker, refreshRevoker: refreshRevoker}
}

func disableReq(t *testing.T, eng disableTestEngine, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/mfa/disable", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	return w
}

// seedDisableEnrolledUser seeds a user with role + MFA-enabled +
// known secret + known recovery codes.
func seedDisableEnrolledUser(eng disableTestEngine, id, orgID uuid.UUID, role domain.UserRole, mfaPolicy *string, secret string, codes []string) *domain.User {
	u := &domain.User{
		ID:               id,
		OrganizationID:   orgID,
		Email:            "self@example.com",
		Role:             role,
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		PasswordHash:     "HASH-CURRENT-PASSWORD",
		MFAEnabled:       true,
		MFASecret:        &secret,
		MFARecoveryCodes: hashCodesForTest(codes),
		MFAPolicy:        mfaPolicy,
	}
	eng.userRepo.byID[id] = u
	return u
}

// ---------- Tests ----------

func TestMFADisable_Unauthenticated401(t *testing.T) {
	eng := newDisableEngine(t, nil)
	w := disableReq(t, eng, map[string]any{"code": "anything"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestMFADisable_MalformedRequest400(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/mfa/disable", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	eng.r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
}

func TestMFADisable_EmptyCodeReturnsInvalidCode(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	w := disableReq(t, eng, map[string]any{"code": ""})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 invalid_code", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_code"`) {
		t.Errorf("body = %q; want invalid_code", w.Body.String())
	}
	stored := eng.userRepo.byID[uid]
	if !stored.MFAEnabled {
		t.Errorf("MFA mutated on empty-code denial: %+v", stored)
	}
	if eng.sessionRevoker.Calls() != nil && len(eng.sessionRevoker.Calls()) != 0 {
		t.Errorf("session revoker fired on denial: %v", eng.sessionRevoker.Calls())
	}
}

func TestMFADisable_NotEnrolledReturns400(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	eng.userRepo.byID[uid] = &domain.User{
		ID:             uid,
		OrganizationID: uuid.New(),
		Email:          "noenroll@example.com",
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		MFAEnabled:     false,
	}
	w := disableReq(t, eng, map[string]any{"code": "000000"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"mfa_not_enrolled"`) {
		t.Errorf("body = %q; want mfa_not_enrolled", w.Body.String())
	}
}

func TestMFADisable_StalePrincipalReturns401Unauthorized(t *testing.T) {
	// Principal points at a UUID with no user row.
	eng := newDisableEngine(t, &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgUser})
	w := disableReq(t, eng, map[string]any{"code": "000000"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
		t.Errorf("body = %q; want unauthorized", w.Body.String())
	}
}

func TestMFADisable_BannedReturns401Unauthorized(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	u := seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	u.Banned = true
	eng.userRepo.byID[uid] = u
	w := disableReq(t, eng, map[string]any{"code": "REC-1"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestMFADisable_DeletedReturns401Unauthorized(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	u := seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	now := time.Now().UTC()
	u.DeletedAt = &now
	eng.userRepo.byID[uid] = u
	w := disableReq(t, eng, map[string]any{"code": "REC-1"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", w.Code)
	}
}

func TestMFADisable_SiteAdminBlockedByPolicy(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleSiteAdmin})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleSiteAdmin, nil, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	w := disableReq(t, eng, map[string]any{"code": "REC-1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"mfa_required_by_policy"`) {
		t.Errorf("body = %q; want mfa_required_by_policy", w.Body.String())
	}
	stored := eng.userRepo.byID[uid]
	if !stored.MFAEnabled {
		t.Errorf("site_admin MFA mutated by denied disable")
	}
}

func TestMFADisable_OrgAdminBlockedByPolicy(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgAdmin})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgAdmin, nil, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	w := disableReq(t, eng, map[string]any{"code": "REC-1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"mfa_required_by_policy"`) {
		t.Errorf("body = %q; want mfa_required_by_policy", w.Body.String())
	}
}

func TestMFADisable_OrgPolicyRequiredBlocks(t *testing.T) {
	uid := uuid.New()
	required := "required"
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, &required, "JBSWY3DPEHPK3PXP", []string{"REC-1"})
	w := disableReq(t, eng, map[string]any{"code": "REC-1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"mfa_required_by_policy"`) {
		t.Errorf("body = %q; want mfa_required_by_policy", w.Body.String())
	}
}

func TestMFADisable_WrongCodeReturnsInvalidCode(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"GOOD-CODE-A", "GOOD-CODE-B"})
	w := disableReq(t, eng, map[string]any{"code": "ZZZZZZZZ"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 invalid_code", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_code"`) {
		t.Errorf("body = %q; want invalid_code", w.Body.String())
	}
	stored := eng.userRepo.byID[uid]
	if !stored.MFAEnabled || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("wrong-code rejection mutated state: %+v", stored)
	}
	if len(eng.sessionRevoker.Calls()) != 0 {
		t.Errorf("session revoker fired on wrong code: %v", eng.sessionRevoker.Calls())
	}
	if len(eng.refreshRevoker.Calls()) != 0 {
		t.Errorf("refresh revoker fired on wrong code: %v", eng.refreshRevoker.Calls())
	}
}

// TestMFADisable_RecoveryCodeHappyPath_FullWireShape doubles as
// the wire-shape pin for the disable surface (204, headers, no
// body, repo cleared, unrelated fields preserved, revoker fan-out
// fired, audit emitted with safe metadata). The TOTP leg is
// already pinned by the service-layer tests in
// internal/service/mfa_enrollment_service_test.go; the handler
// only needs to prove the wire wiring once.
func TestMFADisable_RecoveryCodeHappyPath_FullWireShape(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	secret := "JBSWY3DPEHPK3PXP"
	matched := "RECOVERY-WIRE-CANARY"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"REC-OTHER-A", matched, "REC-OTHER-B"})
	w := disableReq(t, eng, map[string]any{"code": matched})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204; body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q; want empty for 204", body)
	}
	stored := eng.userRepo.byID[uid]
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true after disable")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
	if stored.PasswordHash != "HASH-CURRENT-PASSWORD" {
		t.Errorf("password_hash mutated: %q", stored.PasswordHash)
	}
	if stored.Email != "self@example.com" || stored.Role != domain.RoleOrgUser {
		t.Errorf("identity fields mutated: %+v", stored)
	}
	if calls := eng.sessionRevoker.Calls(); len(calls) != 1 || calls[0].UserID != uid || calls[0].Reason != "mfa_self_disabled" {
		t.Errorf("session revoker calls = %+v", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 1 || calls[0].UserID != uid {
		t.Errorf("refresh revoker calls = %+v", calls)
	}
	var auditMatched int
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditMFADisabled) {
			continue
		}
		auditMatched++
		if got, _ := e.Metadata["reauth_method"].(string); got != "recovery_code" {
			t.Errorf("audit reauth_method = %q; want recovery_code", got)
		}
		for k, v := range e.Metadata {
			if k == "code" || k == "totp_code" || k == "mfa_secret" || k == "recovery_code" || k == "password_hash" || k == "session_id" || k == "refresh_token" {
				t.Errorf("audit metadata leaked banned key %q = %v", k, v)
			}
			if s, ok := v.(string); ok {
				if strings.Contains(s, matched) {
					t.Errorf("audit metadata leaked supplied recovery code: %q", s)
				}
				if strings.Contains(s, secret) {
					t.Errorf("audit metadata leaked MFA secret: %q", s)
				}
			}
		}
	}
	if auditMatched == 0 {
		t.Errorf("missing mfa_disabled audit event")
	}
}

func TestMFADisable_PasswordHappyPath_FullWireShape(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	secret := "JBSWY3DPEHPK3PXP"
	password := "correct-current-password"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"REC-A", "REC-B"})
	w := disableReq(t, eng, map[string]any{"password": password})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204; body=%q", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "" {
		t.Fatalf("body = %q; want empty", body)
	}
	stored := eng.userRepo.byID[uid]
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true after password disable")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
	if stored.PasswordHash != "HASH-CURRENT-PASSWORD" {
		t.Errorf("password_hash mutated: %q", stored.PasswordHash)
	}
	if calls := eng.sessionRevoker.Calls(); len(calls) != 1 || calls[0].UserID != uid {
		t.Errorf("session revoker calls = %+v", calls)
	}
	if calls := eng.refreshRevoker.Calls(); len(calls) != 1 || calls[0].UserID != uid {
		t.Errorf("refresh revoker calls = %+v", calls)
	}
	if eng.userRepo.verifyPasswordCalls != 1 {
		t.Errorf("password verifier calls = %d; want 1", eng.userRepo.verifyPasswordCalls)
	}
	var auditMatched int
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditMFADisabled) {
			continue
		}
		auditMatched++
		if got, _ := e.Metadata["reauth_method"].(string); got != "password" {
			t.Errorf("audit reauth_method = %q; want password", got)
		}
		for k, v := range e.Metadata {
			if k == "code" || k == "password" || k == "totp_code" || k == "mfa_secret" || k == "recovery_code" || k == "password_hash" || k == "session_id" || k == "refresh_token" || k == "token_hash" {
				t.Errorf("audit metadata leaked banned key %q = %v", k, v)
			}
			if s, ok := v.(string); ok {
				for _, banned := range []string{password, "HASH-CURRENT-PASSWORD", secret, "REC-A", "REC-B"} {
					if strings.Contains(s, banned) {
						t.Errorf("audit metadata leaked credential material %q in %q", banned, s)
					}
				}
			}
		}
	}
	if auditMatched == 0 {
		t.Errorf("missing mfa_disabled audit event")
	}
}

func TestMFADisable_WrongPasswordDoesNotMutateOrLeak(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	secret := "JBSWY3DPEHPK3PXP"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"REC-A", "REC-B"})
	w := disableReq(t, eng, map[string]any{"password": "wrong-current-password"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 invalid_code", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_code"`) {
		t.Errorf("body = %q; want invalid_code", body)
	}
	for _, banned := range []string{"wrong-current-password", "HASH-CURRENT-PASSWORD", secret, "REC-A", "REC-B"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaked credential material %q in %q", banned, body)
		}
	}
	stored := eng.userRepo.byID[uid]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("wrong-password rejection mutated state: %+v", stored)
	}
	if len(eng.sessionRevoker.Calls()) != 0 {
		t.Errorf("session revoker fired on wrong password: %v", eng.sessionRevoker.Calls())
	}
	if len(eng.refreshRevoker.Calls()) != 0 {
		t.Errorf("refresh revoker fired on wrong password: %v", eng.refreshRevoker.Calls())
	}
	if len(eng.rec.Events()) != 0 {
		t.Errorf("audit recorded failed password proof: %+v", eng.rec.Events())
	}
}

func TestMFADisable_EmptyPasswordDoesNotMutate(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
	w := disableReq(t, eng, map[string]any{"password": " \t "})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 invalid_code", w.Code)
	}
	if !eng.userRepo.byID[uid].MFAEnabled {
		t.Errorf("empty-password rejection mutated MFAEnabled")
	}
	if eng.userRepo.verifyPasswordCalls != 0 {
		t.Errorf("password verifier calls = %d; want 0", eng.userRepo.verifyPasswordCalls)
	}
}

func TestMFADisable_PasswordPathBlockedByPolicy(t *testing.T) {
	required := "required"
	tests := []struct {
		name   string
		role   domain.UserRole
		policy *string
	}{
		{name: "site_admin", role: domain.RoleSiteAdmin},
		{name: "org_admin", role: domain.RoleOrgAdmin},
		{name: "org_policy_required", role: domain.RoleOrgUser, policy: &required},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid := uuid.New()
			eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: tt.role})
			seedDisableEnrolledUser(eng, uid, uuid.New(), tt.role, tt.policy, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
			w := disableReq(t, eng, map[string]any{"password": "correct-current-password"})
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d; want 403", w.Code)
			}
			if !strings.Contains(w.Body.String(), `"error":"mfa_required_by_policy"`) {
				t.Errorf("body = %q; want mfa_required_by_policy", w.Body.String())
			}
			if eng.userRepo.verifyPasswordCalls != 0 {
				t.Fatalf("password verifier called before policy block: %d", eng.userRepo.verifyPasswordCalls)
			}
			if !eng.userRepo.byID[uid].MFAEnabled {
				t.Errorf("policy denial mutated MFAEnabled")
			}
		})
	}
}

func TestMFADisable_PasswordPathRejectsStaleBannedDeletedOpaquely(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		w := disableReq(t, eng, map[string]any{"password": "correct-current-password"})
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
			t.Fatalf("missing status/body = %d/%q; want 401 unauthorized", w.Code, w.Body.String())
		}
	})
	t.Run("banned", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		u := seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		u.Banned = true
		w := disableReq(t, eng, map[string]any{"password": "correct-current-password"})
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
			t.Fatalf("banned status/body = %d/%q; want 401 unauthorized", w.Code, w.Body.String())
		}
		if eng.userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called for banned user: %d", eng.userRepo.verifyPasswordCalls)
		}
	})
	t.Run("deleted", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		u := seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		now := time.Now().UTC()
		u.DeletedAt = &now
		w := disableReq(t, eng, map[string]any{"password": "correct-current-password"})
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
			t.Fatalf("deleted status/body = %d/%q; want 401 unauthorized", w.Code, w.Body.String())
		}
		if eng.userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called for deleted user: %d", eng.userRepo.verifyPasswordCalls)
		}
	})
}

func TestMFADisable_BothFieldsBehavior(t *testing.T) {
	t.Run("valid non-empty code wins over wrong password", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		w := disableReq(t, eng, map[string]any{"code": "REC-A", "password": "wrong-current-password"})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d; want 204; body=%q", w.Code, w.Body.String())
		}
		if eng.userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called despite non-empty code: %d", eng.userRepo.verifyPasswordCalls)
		}
		var found bool
		for _, e := range eng.rec.Events() {
			if e.Action == string(domain.AuditMFADisabled) {
				found = true
				if got, _ := e.Metadata["reauth_method"].(string); got != "recovery_code" {
					t.Fatalf("reauth_method = %q; want recovery_code", got)
				}
			}
		}
		if !found {
			t.Fatalf("missing audit event")
		}
	})
	t.Run("wrong non-empty code does not fall back to valid password", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		w := disableReq(t, eng, map[string]any{"code": "WRONG-CODE", "password": "correct-current-password"})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d; want 401 invalid_code", w.Code)
		}
		if eng.userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called after wrong non-empty code: %d", eng.userRepo.verifyPasswordCalls)
		}
		if !eng.userRepo.byID[uid].MFAEnabled {
			t.Fatalf("wrong-code rejection mutated MFAEnabled")
		}
	})
	t.Run("empty code uses valid password", func(t *testing.T) {
		uid := uuid.New()
		eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
		seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		w := disableReq(t, eng, map[string]any{"code": "", "password": "correct-current-password"})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d; want 204; body=%q", w.Code, w.Body.String())
		}
		if eng.userRepo.verifyPasswordCalls != 1 {
			t.Fatalf("password verifier calls = %d; want 1", eng.userRepo.verifyPasswordCalls)
		}
		var found bool
		for _, e := range eng.rec.Events() {
			if e.Action == string(domain.AuditMFADisabled) {
				found = true
				if got, _ := e.Metadata["reauth_method"].(string); got != "password" {
					t.Fatalf("reauth_method = %q; want password", got)
				}
			}
		}
		if !found {
			t.Fatalf("missing audit event")
		}
	})
}

func TestMFADisable_RecoveryCodeHappyPath_AndCodeCannotBeReused(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	secret := "JBSWY3DPEHPK3PXP"
	matched := "RECOVERY-CODE-MATCHED"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"RECOVERY-CODE-A", matched, "RECOVERY-CODE-B"})
	w := disableReq(t, eng, map[string]any{"code": matched})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204; body=%q", w.Code, w.Body.String())
	}
	stored := eng.userRepo.byID[uid]
	if stored.MFAEnabled {
		t.Error("MFAEnabled still true")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
	// A second attempt with the same code: MFA is now off, so the
	// second call returns 400 mfa_not_enrolled — not 204. This
	// proves the matched recovery code cannot drive a second
	// successful disable.
	w2 := disableReq(t, eng, map[string]any{"code": matched})
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("second disable status = %d; want 400 mfa_not_enrolled", w2.Code)
	}
	// Audit reauth_method = recovery_code.
	var found bool
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditMFADisabled) {
			continue
		}
		found = true
		if got, _ := e.Metadata["reauth_method"].(string); got != "recovery_code" {
			t.Errorf("audit reauth_method = %q; want recovery_code", got)
		}
		// No leak of matched code.
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, matched) {
				t.Errorf("audit metadata leaked matched recovery code: %q", s)
			}
		}
	}
	if !found {
		t.Error("missing mfa_disabled audit event")
	}
}

func TestMFADisable_RevokerFailuresAreBestEffort(t *testing.T) {
	uid := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	eng.sessionRevoker.Err = errors.New("simulated session revoker outage")
	eng.refreshRevoker.Err = errors.New("simulated refresh revoker outage")
	secret := "JBSWY3DPEHPK3PXP"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"REC-A"})
	w := disableReq(t, eng, map[string]any{"code": "REC-A"})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204 (revoker failures best-effort)", w.Code)
	}
	stored := eng.userRepo.byID[uid]
	if stored.MFAEnabled {
		t.Error("MFAEnabled still true despite successful disable on best-effort path")
	}
	// Audit still fires, but with sessions_revoked=false AND no
	// refresh_tokens_revoked_count key (it is set only on
	// revoker-no-error).
	var matched int
	for _, e := range eng.rec.Events() {
		if e.Action != string(domain.AuditMFADisabled) {
			continue
		}
		matched++
		if sr, ok := e.Metadata["sessions_revoked"].(bool); !ok || sr {
			t.Errorf("audit sessions_revoked = %v; want false", e.Metadata["sessions_revoked"])
		}
		if _, present := e.Metadata["refresh_tokens_revoked_count"]; present {
			t.Errorf("audit refresh_tokens_revoked_count must be absent on error: %v", e.Metadata)
		}
	}
	if matched == 0 {
		t.Error("missing mfa_disabled audit event on best-effort path")
	}
}

func TestMFADisable_OtherUserStateNotAffected(t *testing.T) {
	uid := uuid.New()
	other := uuid.New()
	orgID := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, OrganizationID: orgID, Role: domain.RoleOrgUser})
	secret := "JBSWY3DPEHPK3PXP"
	seedDisableEnrolledUser(eng, uid, orgID, domain.RoleOrgUser, nil, secret, []string{"REC-PRIN"})
	otherSecret := "OTHERSECRETBYTES"
	otherCodes := []string{"OTHER-1", "OTHER-2"}
	eng.userRepo.byID[other] = &domain.User{
		ID:               other,
		OrganizationID:   uuid.New(),
		Email:            "other@example.com",
		Role:             domain.RoleOrgUser,
		MFAEnabled:       true,
		MFASecret:        &otherSecret,
		MFARecoveryCodes: append([]string(nil), otherCodes...),
	}
	w := disableReq(t, eng, map[string]any{"code": "REC-PRIN"})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", w.Code)
	}
	stored := eng.userRepo.byID[other]
	if !stored.MFAEnabled {
		t.Error("other user MFAEnabled mutated")
	}
	if stored.MFASecret == nil || *stored.MFASecret != otherSecret {
		t.Errorf("other user MFASecret mutated: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != len(otherCodes) {
		t.Errorf("other user code count changed: %d → %d", len(otherCodes), len(stored.MFARecoveryCodes))
	}
}

func TestMFADisable_RouteIsPOSTOnly(t *testing.T) {
	uid := uuid.New()
	eng := newDisableEngine(t, &domain.Principal{UserID: uid, Role: domain.RoleOrgUser})
	seedDisableEnrolledUser(eng, uid, uuid.New(), domain.RoleOrgUser, nil, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
	// POSITIVE CONTROL — the route must EXIST, or the method fence below passes
	// against an unmounted path: a 404 to every verb satisfies "not 204" just as
	// well as a correct method rejection does.
	{
		ctlReq := httptest.NewRequest(http.MethodPost, "/api/v1/me/mfa/disable", nil)
		ctlW := httptest.NewRecorder()
		eng.r.ServeHTTP(ctlW, ctlReq)
		if ctlW.Code == http.StatusNotFound {
			t.Fatalf("CONTROL FAILED: POST /api/v1/me/mfa/disable is not mounted (404); the method fence " +
				"below would pass against a route that does not exist")
		}
	}

	for _, verb := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(verb, "/api/v1/me/mfa/disable", nil)
		w := httptest.NewRecorder()
		eng.r.ServeHTTP(w, req)
		if w.Code == http.StatusNoContent {
			t.Errorf("%s /api/v1/me/mfa/disable returned 204; want non-204 (POST-only)", verb)
		}
	}
}
