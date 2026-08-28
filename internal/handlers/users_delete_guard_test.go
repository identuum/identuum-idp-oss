package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// The DELETE /users/:id route admits an org_admin bearing users:delete, not
// site_admin only. Before THE-GUARDED-DELETE the route sat behind
// RequireSiteAdmin, which BOTH blocked the actor AdminPermissionsModel.md
// empowers with "day-to-day control of that organization's resources (users,
// ...)" AND made DeleteUserForActor's org_admin same-org branch unreachable
// dead code (USERS-DELETE-GUARD-1). The service still enforces same-org scope,
// so a cross-org target is the anti-enumeration 404. Reverting the route to
// RequireSiteAdmin makes the same-org case 403 and fails this test.
// RULE: USERS-DELETE-ORGADMIN-SCOPED-1
func TestUsersRoute_OrgAdminDeletesSameOrgUserButNotCrossOrg(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	orgID := uuid.New()
	otherOrg := uuid.New()

	repo := newMemUserRepo()
	same := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Email: "same@x.test"}
	other := &domain.User{ID: uuid.New(), OrganizationID: otherOrg, Role: domain.RoleOrgUser, Email: "other@x.test"}
	if _, err := repo.Create(context.Background(), same); err != nil {
		t.Fatalf("seed same: %v", err)
	}
	if _, err := repo.Create(context.Background(), other); err != nil {
		t.Fatalf("seed other: %v", err)
	}

	deps := UsersHandlerDeps{
		Audit:               audit.NoopService{},
		UserService:         service.NewUserService(nil, repo),
		SessionRevoker:      service.NoopSessionRevoker{},
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
	}
	orgAdmin := &domain.Principal{
		UserID:         uuid.New(),
		Role:           domain.RoleOrgAdmin,
		OrganizationID: orgID,
		Scope:          domain.ScopeUsersDelete,
	}
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(orgAdmin))
	RegisterUsersRoutes(r, deps)

	del := func(id uuid.UUID) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+id.String(), nil)
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := del(same.ID); code != http.StatusOK {
		t.Fatalf("org_admin with users:delete deleting a SAME-org user must reach the handler and 200, got %d", code)
	}
	if code := del(other.ID); code != http.StatusNotFound {
		t.Fatalf("org_admin deleting a CROSS-org user must get the anti-enumeration 404, got %d", code)
	}
}
