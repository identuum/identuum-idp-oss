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
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-DEMOTE item 3: a role change revokes the user's credentials
// FAIL-CLOSED. A failed revocation answers 503 revocation_failed, never a
// 200 that would leave the old role's tokens working.
func TestUsersUpdate_ARoleChangeRevokesFailClosed(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	mem := newMemUserRepo()
	org := uuid.New()
	target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgAdmin, Email: "t@x.test"}
	if _, err := mem.Create(context.Background(), target); err != nil {
		t.Fatalf("seed: %v", err)
	}
	deps := UsersHandlerDeps{
		Audit:          audit.NoopService{},
		UserService:    service.NewUserService(nil, mem),
		SessionRevoker: erroringSessionRevoker{},
	}
	r := gin.New()
	// D-025: a tenant's users are its own org_admin's to change, not a site_admin's.
	r.Use(mw.InjectPrincipalForTest(tenantAdminOf(org)))
	r.PUT("/api/v1/users/:id", HandleUpdateUser(deps))
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+target.ID.String(), strings.NewReader(`{"role":"org_user"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"revocation_failed"`) {
		t.Fatalf("role change with an erroring revoker = %d %s; want 503 {\"error\":\"revocation_failed\"}", w.Code, w.Body.String())
	}
}
