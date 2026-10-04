package handlers

import (
	"context"
	"errors"
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

// OSS-DEMOTE item 4: honest statuses on user PUT and DELETE. Only a missing
// user is 404; a database fault is 500 {"error":"internal_error"}; an
// actor the service cannot identify (domain.ErrUnauthorized) is 401
// {"error":"unauthorized"}, as HandleResetUserMFA answers it.

// faultyDeleteRepo is memUserRepo whose Delete fails like a database would.
type faultyDeleteRepo struct{ *memUserRepo }

func (r faultyDeleteRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	return errors.New("delete users: connection reset by peer")
}

func TestUsersDelete_ADatabaseFaultIsNot404(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	org := uuid.New()
	mem := newMemUserRepo()
	target := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "t@x.test"}
	if _, err := mem.Create(context.Background(), target); err != nil {
		t.Fatalf("seed: %v", err)
	}
	deps := UsersHandlerDeps{
		Audit:               audit.NoopService{},
		UserService:         service.NewUserService(nil, faultyDeleteRepo{mem}),
		SessionRevoker:      service.NoopSessionRevoker{},
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
	}
	r := gin.New()
	// D-025: a site_admin never deletes a tenant's user; its own org_admin does.
	r.Use(mw.InjectPrincipalForTest(tenantAdminOf(org)))
	RegisterUsersRoutes(r, deps)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+target.ID.String(), nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"internal_error"`) {
		t.Fatalf("DELETE with a database fault = %d %s; want 500 {\"error\":\"internal_error\"}", w.Code, w.Body.String())
	}
}

// A handler reached with no principal (the service answers
// domain.ErrUnauthorized) is 401 on both PUT and DELETE, never 500 or 404.
func TestUsersUpdateAndDelete_AnUnidentifiedActorIs401(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	mem := newMemUserRepo()
	target := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "t@x.test"}
	if _, err := mem.Create(context.Background(), target); err != nil {
		t.Fatalf("seed: %v", err)
	}
	deps := UsersHandlerDeps{
		Audit:               audit.NoopService{},
		UserService:         service.NewUserService(nil, mem),
		SessionRevoker:      service.NoopSessionRevoker{},
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
	}
	r := gin.New()
	r.PUT("/api/v1/users/:id", HandleUpdateUser(deps))
	r.DELETE("/api/v1/users/:id", HandleDeleteUser(deps))
	for _, tc := range []struct{ method, body string }{
		{http.MethodPut, `{"active":false}`},
		{http.MethodDelete, ""},
	} {
		req := httptest.NewRequest(tc.method, "/api/v1/users/"+target.ID.String(), strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"unauthorized"`) {
			t.Errorf("%s with no principal = %d %s; want 401 {\"error\":\"unauthorized\"}", tc.method, w.Code, w.Body.String())
		}
	}
}
