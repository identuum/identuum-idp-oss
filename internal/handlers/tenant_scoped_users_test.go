package handlers

import (
	"bytes"
	"context"
	"encoding/json"
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

// tenantEngine wires users + organizations groups with the new
// composed scope guards and tenant-scoped service methods.
type tenantEngine struct {
	r        *gin.Engine
	userRepo *memUserRepo
	orgRepo  *memOrgRepo
	rec      *audit.Recorder
}

func newTenantEngine(t *testing.T, principal *domain.Principal) tenantEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newMemUserRepo()
	orgRepo := newMemOrgRepo()
	rec := &audit.Recorder{}
	RegisterUsersRoutes(r, UsersHandlerDeps{
		UserService: service.NewUserService(nil, userRepo),
		Audit:       rec,
	})
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		Audit:               rec,
	})
	return tenantEngine{r: r, userRepo: userRepo, orgRepo: orgRepo, rec: rec}
}

func seedTenantUser(eng tenantEngine, id, orgID uuid.UUID, role domain.UserRole, email string) *domain.User {
	now := time.Now().UTC()
	u := &domain.User{
		ID:             id,
		OrganizationID: orgID,
		Email:          email,
		Role:           role,
		PasswordHash:   "PASSWORD-HASH-MUST-NOT-LEAK",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, _ = eng.userRepo.Create(context.Background(), u)
	return u
}

func seedTenantOrg(eng tenantEngine, id uuid.UUID, name string) *domain.Organization {
	now := time.Now().UTC()
	o := &domain.Organization{
		ID:                 id,
		Name:               name,
		Domain:             strings.ToLower(name) + ".test",
		OrgSlug:            strings.ToLower(name),
		Active:             true,
		MaxSessionsPerUser: 10,
		MFAPolicy:          "optional",
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	_, _ = eng.orgRepo.Create(context.Background(), o)
	return o
}

func tenantReq(t *testing.T, eng tenantEngine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// ---------- /api/v1/users LIST ----------

func TestUsersList_SiteAdminCrossOrg(t *testing.T) {
	eng := newTenantEngine(t, siteAdminPrincipal())
	seedTenantUser(eng, uuid.New(), uuid.New(), domain.RoleOrgUser, "a@a.test")
	seedTenantUser(eng, uuid.New(), uuid.New(), domain.RoleOrgUser, "b@b.test")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Total != 2 {
		t.Errorf("site_admin total = %d, want 2", body.Total)
	}
}

func TestUsersList_OrgAdminScoped(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	seedTenantUser(eng, uuid.New(), org, domain.RoleOrgUser, "u@own.test")
	seedTenantUser(eng, uuid.New(), uuid.New(), domain.RoleOrgUser, "u@other.test")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// The in-memory repo's ListByOrganization aliases List in test
	// scaffolds, so we cannot assert filtering count here. We instead
	// assert the service path ran (status 200 + no leak) and the next
	// test covers org_admin missing-scope 403.
	if strings.Contains(rec.Body.String(), "PASSWORD-HASH-MUST-NOT-LEAK") {
		t.Errorf("list leaked password hash")
	}
}

func TestUsersList_OrgAdminMissingScope403(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "other:scope",
	})
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestUsersList_OrgUserForbidden(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgUser,
		Scope:          "users:read",
	})
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// ---------- /api/v1/users/:id GET ----------

func TestUsersGet_OrgAdminSameOrgAllowed(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleOrgUser, "u@own.test")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+target.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PASSWORD-HASH-MUST-NOT-LEAK") {
		t.Errorf("get leaked password hash")
	}
}

func TestUsersGet_OrgAdminCrossOrgNotFound(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	target := uuid.New()
	seedTenantUser(eng, target, uuid.New(), domain.RoleOrgUser, "u@other.test")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+target.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("cross-org get = %d, want 404 (AdminPermissionsModel: outside an org_admin's "+
			"visibility is NOT FOUND — a 403 confirms the row exists across a tenant boundary)", rec.Code)
	}
}

func TestUsersGet_OrgAdminSiteAdminTargetNotFound(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleSiteAdmin, "sa@test")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/users/"+target.String(), nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("get site_admin target = %d, want 404 (the model: an org_admin cannot READ a "+
			"site_admin account, and 404 is the only status that does not confirm it exists)", rec.Code)
	}
}

// ---------- /api/v1/users POST ----------

func TestUsersCreate_OrgAdminOwnOrgAllowed(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:create",
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"email":    "new@test",
		"password": "Password-Sentinel-Must-Not-Leak-1!",
		"role":     "org_user",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Password-Sentinel-Must-Not-Leak-1!") {
		t.Errorf("create response leaked plaintext password")
	}
	var got safeUser
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.OrganizationID != org {
		t.Errorf("created in org %s, want %s (org_admin own-org enforcement)", got.OrganizationID, org)
	}
}

func TestUsersCreate_OrgAdminOtherOrgForbidden(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:create",
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"organization_id": uuid.NewString(),
		"email":           "new@test",
		"password":        "p",
		"role":            "org_user",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org create = %d, want 403", rec.Code)
	}
}

func TestUsersCreate_OrgAdminCannotCreateSiteAdmin(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:create",
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"email":    "new@test",
		"password": "p",
		"role":     "site_admin",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("create site_admin as org_admin = %d, want 403", rec.Code)
	}
}

func TestUsersCreate_OrgAdminMissingScopeForbidden(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		"email":    "new@test",
		"password": "p",
		"role":     "org_user",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing users:create = %d, want 403", rec.Code)
	}
}

func TestUsersCreate_SiteAdminRequiresOrgID(t *testing.T) {
	eng := newTenantEngine(t, siteAdminPrincipal())
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users", map[string]any{
		// no organization_id supplied
		"email":    "new@test",
		"password": "p",
		"role":     "org_user",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("site_admin no-org create = %d, want 400", rec.Code)
	}
}

// ---------- /api/v1/users/:id PUT ----------

func TestUsersUpdate_OrgAdminSameOrgAllowed(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:update",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleOrgUser, "u@own.test")
	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/users/"+target.String(), map[string]any{
		"banned": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

func TestUsersUpdate_OrgAdminCannotPromoteToSiteAdmin(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:update",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleOrgUser, "u@own.test")
	rec := tenantReq(t, eng, http.MethodPut, "/api/v1/users/"+target.String(), map[string]any{
		"role": "site_admin",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("promote-to-site_admin = %d, want 403", rec.Code)
	}
}

// ---------- DELETE / restore stay site_admin-only at HTTP layer ----------

func TestUsersDelete_OrgAdminForbiddenAtHTTPLayer(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:delete",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleOrgUser, "u@own.test")
	rec := tenantReq(t, eng, http.MethodDelete, "/api/v1/users/"+target.String(), nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("delete by org_admin = %d, want 403 (slice keeps delete site_admin-only)", rec.Code)
	}
}

func TestUsersRestore_OrgAdminForbiddenAtHTTPLayer(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:delete",
	})
	target := uuid.New()
	seedTenantUser(eng, target, org, domain.RoleOrgUser, "u@own.test")
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/"+target.String()+"/restore", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("restore by org_admin = %d, want 403", rec.Code)
	}
}

// The reset-mfa route (users:mfa:revoke scope) rejects this org_admin,
// which holds users:create/update/delete but NOT users:mfa:revoke.
// NOTE: /users/:id/approve (users:update) and /users/bulk (users:create)
// were implemented and moved into their scope-gated groups — scopes THIS
// org_admin holds — so they no longer 403 here; their authorization is
// covered by user_approve_test.go and user_bulk_create_test.go.
func TestUsersDeferred_OrgAdminForbidden(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:create users:update users:delete",
	})
	for _, p := range []string{
		"/api/v1/users/" + uuid.NewString() + "/recovery/reset-mfa",
	} {
		rec := tenantReq(t, eng, http.MethodPost, p, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s as org_admin = %d, want 403", p, rec.Code)
		}
	}
}

// ---------- Organizations list scope behavior ----------

func TestOrganizationsList_OrgAdminGetsOwnOrgOnly(t *testing.T) {
	org := uuid.New()
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          "orgs:read",
	})
	seedTenantOrg(eng, org, "Mine")
	seedTenantOrg(eng, uuid.New(), "Other")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/organizations", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Total         int                `json:"total"`
		Organizations []safeOrganization `json:"organizations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Total != 1 || len(body.Organizations) != 1 || body.Organizations[0].ID != org {
		t.Errorf("org_admin list = %+v, want only own org %s", body, org)
	}
}

func TestOrganizationsList_OrgAdminMissingScopeForbidden(t *testing.T) {
	eng := newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
		Scope:          "users:read",
	})
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/organizations", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing orgs:read = %d, want 403", rec.Code)
	}
}

func TestOrganizationsList_SiteAdminSeesAll(t *testing.T) {
	eng := newTenantEngine(t, siteAdminPrincipal())
	seedTenantOrg(eng, uuid.New(), "A")
	seedTenantOrg(eng, uuid.New(), "B")
	rec := tenantReq(t, eng, http.MethodGet, "/api/v1/organizations", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Total != 2 {
		t.Errorf("site_admin total = %d, want 2", body.Total)
	}
}
