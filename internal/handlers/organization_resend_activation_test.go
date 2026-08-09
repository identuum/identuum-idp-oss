package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// mockActivationResender is a controllable OrgActivationResender: it
// records invocations (so the "send seam invoked" assertion is exact) and
// returns whatever outcome a test configures.
type mockActivationResender struct {
	called  int
	lastOrg uuid.UUID
	raw     string
	expires time.Time
	email   string
	err     error
}

func (m *mockActivationResender) ResendActivationToken(_ context.Context, orgID uuid.UUID) (string, time.Time, string, error) {
	m.called++
	m.lastOrg = orgID
	return m.raw, m.expires, m.email, m.err
}

func newResendEngine(t *testing.T, principal *domain.Principal, resender OrgActivationResender) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	// OrganizationRepo non-nil so the live surface mounts (reuses the
	// stub from organization_admin_recovery_test.go). The resend handler
	// itself uses only ActivationResender.
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationRepo:   stubAdminRecOrgRepo{org: &domain.Organization{}},
		ActivationResender: resender,
	})
	return r
}

func doResendPOST(t *testing.T, r *gin.Engine, orgID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID+"/resend-activation", nil))
	return rec
}

// (a) no longer 501; a site_admin resend → 200, the send seam is invoked
// exactly once for the target org, and the fresh token is echoed.
func TestResendActivationHandler_SiteAdmin_Succeeds(t *testing.T) {
	orgID := uuid.New()
	m := &mockActivationResender{raw: "RAW-ACTIVATION-TOKEN-XYZ", email: "admin@t.test", expires: time.Now().Add(time.Hour)}
	r := newResendEngine(t, siteAdminPrincipal(), m)
	rec := doResendPOST(t, r, orgID.String())
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("resend still returns 501 — the OSS port did not take effect")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s want 200", rec.Code, rec.Body.String())
	}
	if m.called != 1 {
		t.Fatalf("send seam invoked %d times, want 1", m.called)
	}
	if m.lastOrg != orgID {
		t.Errorf("resend called for org %s, want %s", m.lastOrg, orgID)
	}
	var body struct {
		Success         bool   `json:"success"`
		ActivationToken string `json:"activation_token"`
		AdminEmail      string `json:"admin_email"`
		ExpiresAt       string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Success || body.ActivationToken != "RAW-ACTIVATION-TOKEN-XYZ" || body.AdminEmail != "admin@t.test" {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
	if body.ExpiresAt == "" {
		t.Errorf("expires_at missing")
	}
}

// (b) auth: a non-site_admin (org_admin, same or cross org) is rejected
// 403 by the siteOnly group's RequireSiteAdmin — the seam never runs.
func TestResendActivationHandler_OrgAdmin_Forbidden(t *testing.T) {
	m := &mockActivationResender{raw: "x"}
	r := newResendEngine(t, &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgAdmin, Scope: "orgs:update"}, m)
	rec := doResendPOST(t, r, uuid.NewString())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_admin resend = %d, want 403", rec.Code)
	}
	if m.called != 0 {
		t.Errorf("send seam invoked despite 403 (called=%d)", m.called)
	}
}

// (b) auth: unauthenticated → 401, seam never runs.
func TestResendActivationHandler_Unauthenticated_401(t *testing.T) {
	m := &mockActivationResender{raw: "x"}
	r := newResendEngine(t, nil, m)
	rec := doResendPOST(t, r, uuid.NewString())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated resend = %d, want 401", rec.Code)
	}
	if m.called != 0 {
		t.Errorf("send seam invoked despite 401")
	}
}

// (c) guards: each service sentinel maps to the correct 4xx — never a
// silent success.
func TestResendActivationHandler_GuardMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"missing_org", domain.ErrOrganizationNotFound, http.StatusNotFound},
		{"already_active", service.ErrOrganizationAlreadyActive, http.StatusConflict},
		{"no_admin", service.ErrOrganizationActivationNoAdmin, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockActivationResender{err: tc.err}
			r := newResendEngine(t, siteAdminPrincipal(), m)
			rec := doResendPOST(t, r, uuid.NewString())
			if rec.Code != tc.want {
				t.Fatalf("%s: status=%d want %d; body=%s", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// A non-UUID :id is a 400 before the seam runs.
func TestResendActivationHandler_InvalidID_400(t *testing.T) {
	m := &mockActivationResender{raw: "x"}
	r := newResendEngine(t, siteAdminPrincipal(), m)
	rec := doResendPOST(t, r, "not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid id = %d, want 400", rec.Code)
	}
	if m.called != 0 {
		t.Errorf("seam invoked on invalid id")
	}
}

// An unwired resender fails closed with 503, not a misleading success.
func TestResendActivationHandler_Unwired_503(t *testing.T) {
	r := newResendEngine(t, siteAdminPrincipal(), nil)
	rec := doResendPOST(t, r, uuid.NewString())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired resend = %d, want 503", rec.Code)
	}
}
