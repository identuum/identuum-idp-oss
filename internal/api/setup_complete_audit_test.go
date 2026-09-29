package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// OSS-POLISH item 5 (audit F4): setup completion and the first admin's
// creation were not audited. A successful POST /api/setup/complete now records
// setup.completed (the first organization) and user_created (the pinned
// site_admin), actor type setup_token — the wizard's caller holds only the
// setup token. A refused completion records nothing.
func TestSetupComplete_IsAudited(t *testing.T) {
	orgID := uuid.New()
	fake := &fakeSetupService{completeOut: &setup.CompleteOutput{
		State: domain.SetupStatusComplete, OrganizationID: orgID, OrganizationName: "Acme",
		AdminEmail: "owner@acme.test", LoginEmail: "site_admin@system.local",
	}}
	rec := &audit.Recorder{}
	gin.SetMode(gin.ReleaseMode)
	e := gin.New()
	RegisterSetupRoutes(e, SetupRoutesDeps{Service: fake, DataDir: t.TempDir(), Audit: rec})

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/setup/complete",
			strings.NewReader(`{"setup_token":"t","organization_name":"Acme","admin_email":"owner@acme.test","admin_password":"setup-audit-pw-9x"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		return w.Code
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	events := rec.Events()
	if len(events) != 2 || events[0].Action != "setup.completed" || events[1].Action != string(domain.AuditUserCreated) {
		t.Fatalf("audit = %+v, want [setup.completed user_created]", events)
	}
	if events[0].OrganizationID != orgID || events[0].ActorType != "setup_token" {
		t.Fatalf("setup.completed org/actor = %v/%q, want %v/setup_token", events[0].OrganizationID, events[0].ActorType, orgID)
	}
	if events[1].SubjectID.String() != domain.SiteAdminID || events[1].Metadata["role"] != string(domain.RoleSiteAdmin) {
		t.Fatalf("user_created subject/role = %v/%v, want the site_admin", events[1].SubjectID, events[1].Metadata["role"])
	}
	for _, ev := range events {
		for k, v := range ev.Metadata {
			if s, ok := v.(string); ok && (s == "t" || s == "setup-audit-pw-9x" || s == "owner@acme.test") {
				t.Fatalf("audit metadata %q carries the setup token or password", k)
			}
		}
	}

	fake.completeOut, fake.completeErr = nil, setup.ErrTokenInvalid
	rec2 := &audit.Recorder{}
	e2 := gin.New()
	RegisterSetupRoutes(e2, SetupRoutesDeps{Service: fake, DataDir: t.TempDir(), Audit: rec2})
	e = e2
	if code := post(); code != http.StatusUnauthorized {
		t.Fatalf("refused: status = %d, want 401", code)
	}
	if rec2.Len() != 0 {
		t.Fatalf("a refused completion recorded %d events, want 0", rec2.Len())
	}
}
