package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-BINARIES item 2: the site-admin list offers "Reactivate" on a
// never-activated organization, and PUT {"active":true} flipped it active.
// That breaks the organization's own activation: consume answers
// organization_already_active, so the pending administrator can never set a
// password. An organization whose administrators have never activated is
// activated by its administrator's link (re-issue it with
// resend-activation); PUT active=true answers 409 activation_pending and
// changes nothing. A shell organization (no admin) and one with an
// activated admin still reactivate — site_admin's lifecycle authority.
func TestUpdateOrganization_ReactivatingANeverActivatedOrgIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name    string
		counter pendingAwareCounter
		want    int
	}{
		{"pending administrator, never activated", pendingAwareCounter{admins: 1, verified: 0, blocking: 1}, http.StatusConflict},
		{"pending administrator, activation expired", pendingAwareCounter{admins: 1, verified: 0, blocking: 0}, http.StatusConflict},
		{"shell organization (no admin)", pendingAwareCounter{}, http.StatusOK},
		{"activated administrator (deactivated later)", pendingAwareCounter{admins: 1, verified: 1, blocking: 1}, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
			id := uuid.New()
			_, _ = repo.memOrgRepo.Create(context.Background(), &domain.Organization{ID: id, Name: "Acme", Domain: "acme.test", Active: false})
			deps := OrganizationsHandlerDeps{
				Audit:               audit.NoopService{},
				OrganizationService: service.NewOrganizationService(nil, repo),
				AdminCounter:        tt.counter,
			}
			code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"active":true}`, HandleUpdateOrganization(deps))
			if code != tt.want {
				t.Fatalf("PUT active=true answered %d, want %d", code, tt.want)
			}
			if tt.want == http.StatusConflict && repo.updateCalls != 0 {
				t.Fatalf("the refused reactivation still reached the repository %d time(s)", repo.updateCalls)
			}
		})
	}
}

// OSS-FINAL item 2: the refusal points the operator to the console action
// that re-issues the link (the organization's page, "Re-issue activation
// link"), not to a raw API route.
func TestUpdateOrganization_ActivationPendingNamesTheConsoleAction(t *testing.T) {
	repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
	id := uuid.New()
	_, _ = repo.memOrgRepo.Create(context.Background(), &domain.Organization{ID: id, Name: "Acme", Domain: "acme.test", Active: false})
	deps := OrganizationsHandlerDeps{
		Audit:               audit.NoopService{},
		OrganizationService: service.NewOrganizationService(nil, repo),
		AdminCounter:        pendingAwareCounter{admins: 1, verified: 0, blocking: 1},
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(siteAdminActor()))
	r.PUT("/o/:id", HandleUpdateOrganization(deps))
	req := httptest.NewRequest(http.MethodPut, "/o/"+id.String(), strings.NewReader(`{"active":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var body struct{ Error, Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusConflict || body.Error != "activation_pending" {
		t.Fatalf("PUT active=true answered %d %q (%v), want 409 activation_pending", rec.Code, rec.Body.String(), err)
	}
	if !strings.Contains(body.Message, "Re-issue activation link") {
		t.Errorf("the message does not name the console action: %q", body.Message)
	}
	if strings.Contains(body.Message, "/api/v1/") {
		t.Errorf("the message names a raw API route instead of the console action: %q", body.Message)
	}
}
