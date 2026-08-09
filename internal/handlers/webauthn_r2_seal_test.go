package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// r2StubLoginFinisher is a stub WebAuthnLoginFinisher: the assertion has
// already "verified" — it returns the resolved user + the UV flag the test
// controls, so the seal + MFA gate can be exercised without a real
// WebAuthn ceremony. The underlying verification path (FinishLogin) is
// covered unchanged by the existing webauthn_service_test suite.
type r2StubLoginFinisher struct {
	user *domain.User
	uv   bool
}

func (s r2StubLoginFinisher) FinishLogin(_ context.Context, _ string, _ *http.Request) (*domain.WebAuthnCredential, *domain.User, bool, error) {
	return &domain.WebAuthnCredential{ID: uuid.New()}, s.user, s.uv, nil
}

// r2StubUserOrgLookup returns the org-bearing user projection.
type r2StubUserOrgLookup struct{ user *domain.User }

func (s r2StubUserOrgLookup) GetByIDWithOrg(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	return s.user, nil
}

func r2Ptr(s string) *string { return &s }

func r2Deps(user *domain.User, uv bool) WebAuthnHandlerDeps {
	return WebAuthnHandlerDeps{
		Audit:         audit.NoopService{},
		UserSession:   service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{}),
		LoginFinisher: r2StubLoginFinisher{user: user, uv: uv},
		UserOrgLookup: r2StubUserOrgLookup{user: user},
	}
}

func r2RunFinish(deps WebAuthnHandlerDeps) (int, string) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/finish", HandleWebAuthnLoginFinish(deps))
	req := httptest.NewRequest(http.MethodPost, "/finish?session_id=abc", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// (a) idp_only org + org_user passkey → REJECTED by the seal; no session.
func TestWebAuthnFinish_IDPOnlySealRejects(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "u@x.test", OrgAuthPolicy: r2Ptr(domain.AuthPolicyIDPOnly)}
	code, body := r2RunFinish(r2Deps(user, true))
	t.Logf("EVIDENCE (a) idp_only seal: status=%d body=%s", code, body)
	if code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 (idp_only seal blocks org_user WebAuthn)", code)
	}
	if !strings.Contains(body, "invalid_credentials") {
		t.Errorf("want invalid_credentials (same as password path); got %s", body)
	}
	if strings.Contains(body, "session_id") {
		t.Errorf("seal must NOT create a session; body=%s", body)
	}
}

// (b) non-idp_only org → WebAuthn login still succeeds (no regression).
func TestWebAuthnFinish_NonIDPOnlySucceeds(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "ok@x.test"} // nil OrgAuthPolicy ⇒ permissive
	code, body := r2RunFinish(r2Deps(user, true))
	t.Logf("EVIDENCE (b) non-idp_only: status=%d", code)
	if code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (non-idp_only succeeds); body=%s", code, body)
	}
	if !strings.Contains(body, "session_id") {
		t.Errorf("expected a created session; body=%s", body)
	}
}

// (c) org requires MFA + UV-verified assertion → login completes (UV satisfies MFA).
func TestWebAuthnFinish_MFARequired_UVSatisfies(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "uv@x.test", MFAPolicy: r2Ptr("required")}
	code, body := r2RunFinish(r2Deps(user, true)) // UV present
	t.Logf("EVIDENCE (c) MFA required + UV: status=%d", code)
	if code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (UV-verified WebAuthn satisfies MFA); body=%s", code, body)
	}
	if !strings.Contains(body, "session_id") {
		t.Errorf("expected a created session; body=%s", body)
	}
}

// (d) org requires MFA + presence-only assertion (no UV) → NOT fully
// authenticated; second factor required; no session.
func TestWebAuthnFinish_MFARequired_NoUVRejected(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "nouv@x.test", MFAPolicy: r2Ptr("required")}
	code, body := r2RunFinish(r2Deps(user, false)) // presence-only, no UV
	t.Logf("EVIDENCE (d) MFA required + no UV: status=%d body=%s", code, body)
	if code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 (presence-only WebAuthn does not satisfy MFA)", code)
	}
	if !strings.Contains(body, "mfa_required") {
		t.Errorf("want mfa_required; got %s", body)
	}
	if strings.Contains(body, "session_id") {
		t.Errorf("must NOT create a session when MFA unsatisfied; body=%s", body)
	}
}
