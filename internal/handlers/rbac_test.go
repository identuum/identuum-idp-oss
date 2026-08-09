package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memOrgRoleRepo mirrors the service test's in-memory repo but
// lives in handlers package so the test compiles against an
// independent fixture.
type memOrgRoleRepo struct {
	mu        sync.Mutex
	roles     map[uuid.UUID]*domain.OrgRole
	userRoles map[uuid.UUID][]uuid.UUID
}

func newMemOrgRoleRepo() *memOrgRoleRepo {
	return &memOrgRoleRepo{
		roles:     map[uuid.UUID]*domain.OrgRole{},
		userRoles: map[uuid.UUID][]uuid.UUID{},
	}
}

func (r *memOrgRoleRepo) Create(_ context.Context, role *domain.OrgRole) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	r.roles[role.ID] = role
	return nil
}
func (r *memOrgRoleRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.roles[id], nil
}
func (r *memOrgRoleRepo) ListByOrg(_ context.Context, orgID uuid.UUID) ([]*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrgRole, 0)
	for _, v := range r.roles {
		if v.OrgID == orgID {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *memOrgRoleRepo) Update(_ context.Context, role *domain.OrgRole) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roles[role.ID] = role
	return nil
}
func (r *memOrgRoleRepo) Delete(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.roles, id)
	return nil
}
func (r *memOrgRoleRepo) AddScope(_ context.Context, roleID, _ uuid.UUID, scopeName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if role, ok := r.roles[roleID]; ok {
		role.Scopes = append(role.Scopes, scopeName)
	}
	return nil
}
func (r *memOrgRoleRepo) RemoveScope(_ context.Context, roleID uuid.UUID, scopeName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, ok := r.roles[roleID]
	if !ok {
		return nil
	}
	out := role.Scopes[:0]
	for _, s := range role.Scopes {
		if s != scopeName {
			out = append(out, s)
		}
	}
	role.Scopes = out
	return nil
}
func (r *memOrgRoleRepo) AssignRoleToUser(_ context.Context, userID, roleID, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userRoles[userID] = append(r.userRoles[userID], roleID)
	return nil
}
func (r *memOrgRoleRepo) RemoveRoleFromUser(_ context.Context, userID, roleID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.userRoles[userID][:0]
	for _, rid := range r.userRoles[userID] {
		if rid != roleID {
			out = append(out, rid)
		}
	}
	r.userRoles[userID] = out
	return nil
}
func (r *memOrgRoleRepo) ListRolesForUser(_ context.Context, userID uuid.UUID) ([]*domain.OrgRole, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrgRole, 0)
	for _, rid := range r.userRoles[userID] {
		if role, ok := r.roles[rid]; ok {
			out = append(out, role)
		}
	}
	return out, nil
}
func (r *memOrgRoleRepo) ListUserIDsForRole(_ context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uuid.UUID, 0)
	for uid, rids := range r.userRoles {
		for _, rid := range rids {
			if rid == roleID {
				out = append(out, uid)
				break
			}
		}
	}
	return out, nil
}
func (r *memOrgRoleRepo) GetScopesForUser(_ context.Context, _ uuid.UUID, _ *uuid.UUID) ([]string, error) {
	panic("not used")
}

// rbacEngine wires the RBAC route family with a caller-supplied
// FeatureGate so the same fixture can pin gated and ungated behavior.
type rbacEngine struct {
	r        *gin.Engine
	repo     *memOrgRoleRepo
	userRepo *memUserRepo
	rec      *audit.Recorder
}

func newRBACEngine(t *testing.T, principal *domain.Principal, gate features.FeatureGate) rbacEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	repo := newMemOrgRoleRepo()
	userRepo := newMemUserRepo()
	rec := &audit.Recorder{}
	RegisterRBACRoutes(r, RBACHandlerDeps{
		OrgRoleService: service.NewOrgRoleService(nil, repo, nil).WithUserRepository(userRepo),
		Audit:          rec,
		FeatureGate:    gate,
	})
	return rbacEngine{r: r, repo: repo, userRepo: userRepo, rec: rec}
}

func rbacReq(t *testing.T, eng rbacEngine, method, path string, body any) *httptest.ResponseRecorder {
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

// ---------- Routes-absent without deps ----------

func TestRBAC_RoutesAbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRBACRoutes(r, RBACHandlerDeps{}) // OrgRoleService nil
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me/roles", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (no service → no routes)", rec.Code)
	}
}

// ---------- Feature gate ----------

func TestRBAC_ClosedGateReturns403(t *testing.T) {
	eng := newRBACEngine(t, siteAdminPrincipal(), features.ClosedGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/me/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ClosedGate me/roles status = %d, want 403", rec.Code)
	}
	if !contains(rec.Body.String(), `"feature":"authorization_server"`) {
		t.Errorf("body missing feature label: %q", rec.Body.String())
	}
}

func TestRBAC_OpenGateAllowsThroughAuth(t *testing.T) {
	p := &domain.Principal{Role: domain.RoleOrgUser, UserID: uuid.New(), OrganizationID: uuid.New()}
	eng := newRBACEngine(t, p, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/me/roles", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("OpenGate me/roles status = %d, want 200", rec.Code)
	}
}

func TestRBAC_OrgRolesClosedGate(t *testing.T) {
	org := uuid.New()
	eng := newRBACEngine(t, &domain.Principal{
		Role: domain.RoleSiteAdmin,
	}, features.ClosedGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("ClosedGate org roles status = %d, want 403", rec.Code)
	}
}

// ---------- /me/roles auth ----------

func TestRBAC_MeRolesUnauthenticated401(t *testing.T) {
	eng := newRBACEngine(t, nil, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/me/roles", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRBAC_MeRolesAnyAuthenticatedAllowed(t *testing.T) {
	p := &domain.Principal{Role: domain.RoleOrgUser, UserID: uuid.New(), OrganizationID: uuid.New()}
	eng := newRBACEngine(t, p, features.OpenGate{})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: p.OrganizationID, Name: "Mine"}
	_ = eng.repo.Create(context.Background(), role)
	_ = eng.repo.AssignRoleToUser(context.Background(), p.UserID, role.ID, uuid.New())
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/me/roles", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	var body struct {
		Roles []safeOrgRole `json:"roles"`
		Count int           `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Count != 1 || body.Roles[0].ID != role.ID {
		t.Errorf("unexpected body: %+v", body)
	}
}

// ---------- /organizations/:id/roles read ----------

func TestRBAC_ListOrgRolesSameOrgAdminAllowed(t *testing.T) {
	org := uuid.New()
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "orgs:read",
	}, features.OpenGate{})
	_ = eng.repo.Create(context.Background(), &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "A"})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/roles", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

func TestRBAC_ListOrgRolesCrossOrgAdminForbidden(t *testing.T) {
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Scope:          "orgs:read",
	}, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org list = %d, want 403", rec.Code)
	}
}

func TestRBAC_ListOrgRolesMissingScope403(t *testing.T) {
	org := uuid.New()
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "other:scope",
	}, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing-scope list = %d, want 403", rec.Code)
	}
}

func TestRBAC_ListOrgRolesOrgUserForbidden(t *testing.T) {
	org := uuid.New()
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgUser,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "orgs:read",
	}, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("org_user status = %d, want 403", rec.Code)
	}
}

// ---------- /organizations/:id/roles create + audit ----------

func TestRBAC_CreateOrgRoleSameOrgAdminAllowed(t *testing.T) {
	org := uuid.New()
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "orgs:update",
	}, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/organizations/"+org.String()+"/roles", map[string]any{
		"name":        "Reviewers",
		"description": "Read access to billing scopes",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	var saw bool
	for _, e := range eng.rec.Events() {
		if e.Action == "org_role.created" {
			saw = true
			// Audit metadata must not carry secret-like material.
			for _, v := range e.Metadata {
				if s, ok := v.(string); ok && contains(s, "Bearer") {
					t.Errorf("audit metadata contains bearer-looking string: %v", v)
				}
			}
		}
	}
	if !saw {
		t.Errorf("missing org_role.created audit event")
	}
}

func TestRBAC_CreateOrgRoleCrossOrgAdminForbidden(t *testing.T) {
	eng := newRBACEngine(t, &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Scope:          "orgs:update",
	}, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/organizations/"+uuid.NewString()+"/roles", map[string]any{
		"name": "X",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org create = %d, want 403", rec.Code)
	}
}

func TestRBAC_CreateOrgRoleSiteAdminAcrossOrgsAllowed(t *testing.T) {
	eng := newRBACEngine(t, siteAdminPrincipal(), features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/organizations/"+uuid.NewString()+"/roles", map[string]any{
		"name": "Cross-Tenant",
	})
	if rec.Code != http.StatusCreated {
		t.Errorf("site_admin cross-org create = %d, want 201", rec.Code)
	}
}

// ---------- /users/:id/roles ----------

func TestRBAC_AssignRoleSameOrgAdminAllowed(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "orgs:update",
	}
	eng := newRBACEngine(t, p, features.OpenGate{})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "Same"}
	_ = eng.repo.Create(context.Background(), role)
	target := uuid.New()
	// Seed the target user in the role's org so the new
	// target-user tenant guard finds a valid same-org user.
	_, _ = eng.userRepo.Create(context.Background(), &domain.User{
		ID: target, OrganizationID: org, Email: "u@test", Role: domain.RoleOrgUser, PasswordHash: "h",
	})
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/users/"+target.String()+"/roles", map[string]any{
		"role_id": role.ID,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

func TestRBAC_AssignRoleCrossOrgForbidden(t *testing.T) {
	p := &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Scope:          "orgs:update",
	}
	eng := newRBACEngine(t, p, features.OpenGate{})
	otherRole := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "Other"}
	_ = eng.repo.Create(context.Background(), otherRole)
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/roles", map[string]any{
		"role_id": otherRole.ID,
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-org assign = %d, want 403", rec.Code)
	}
}

func TestRBAC_AssignRoleMissingScope403(t *testing.T) {
	p := &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Scope:          "orgs:read",
	}
	eng := newRBACEngine(t, p, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodPost, "/api/v1/users/"+uuid.NewString()+"/roles", map[string]any{
		"role_id": uuid.NewString(),
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing orgs:update = %d, want 403", rec.Code)
	}
}

func TestRBAC_ListUserRolesSiteAdminCrossOrg(t *testing.T) {
	eng := newRBACEngine(t, siteAdminPrincipal(), features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/users/"+uuid.NewString()+"/roles", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("site_admin list user roles = %d, want 200", rec.Code)
	}
}

func TestRBAC_RemoveRoleSameOrgAdminAllowed(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "orgs:update",
	}
	eng := newRBACEngine(t, p, features.OpenGate{})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = eng.repo.Create(context.Background(), role)
	target := uuid.New()
	_ = eng.repo.AssignRoleToUser(context.Background(), target, role.ID, uuid.New())
	rec := rbacReq(t, eng, http.MethodDelete, "/api/v1/users/"+target.String()+"/roles/"+role.ID.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove same-org status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

// ---------- Unauthenticated on protected routes ----------

func TestRBAC_OrgRolesUnauthenticated401(t *testing.T) {
	eng := newRBACEngine(t, nil, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/roles", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", rec.Code)
	}
}

// ---------- ClosedGate denial emits feature.denied audit ----------

func TestRBAC_ClosedGateEmitsFeatureDeniedAudit(t *testing.T) {
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: uuid.New(), Scope: "orgs:read"}
	eng := newRBACEngine(t, p, features.ClosedGate{})
	_ = rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+p.OrganizationID.String()+"/roles", nil)
	var seenAction string
	var safeMeta map[string]any
	for _, e := range eng.rec.Events() {
		if e.Action == "feature.denied" {
			seenAction = e.Action
			safeMeta = e.Metadata
		}
	}
	if seenAction != "feature.denied" {
		t.Fatalf("expected feature.denied audit event, got %+v", eng.rec.Events())
	}
	if safeMeta["feature"] != features.AuthorizationServer {
		t.Errorf("metadata.feature = %v, want authorization_server", safeMeta["feature"])
	}
	if safeMeta["actor_role"] != string(domain.RoleOrgAdmin) {
		t.Errorf("metadata.actor_role = %v, want org_admin", safeMeta["actor_role"])
	}
	// Ensure none of the principal's secret-bearing fields cross
	// into the audit metadata.
	for k := range safeMeta {
		switch k {
		case "user_id", "session_id", "scope", "email", "client_secret", "token":
			t.Errorf("audit metadata leaked %s", k)
		}
	}
}

// ---------- Scope.denied audit via the live RBAC group ----------

func TestRBAC_OrgRolesMissingScopeEmitsScopeDenied(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{
		Role:           domain.RoleOrgAdmin,
		UserID:         uuid.New(),
		OrganizationID: org,
		Scope:          "wrong:scope",
	}
	eng := newRBACEngine(t, p, features.OpenGate{})
	rec := rbacReq(t, eng, http.MethodGet, "/api/v1/organizations/"+org.String()+"/roles", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var sawScope bool
	for _, e := range eng.rec.Events() {
		if e.Action == "scope.denied" {
			sawScope = true
			required, _ := e.Metadata["required_scopes"].([]string)
			if len(required) != 1 || required[0] != "orgs:read" {
				t.Errorf("required_scopes = %v, want [orgs:read]", required)
			}
			if e.Metadata["actor_role"] != string(domain.RoleOrgAdmin) {
				t.Errorf("actor_role = %v", e.Metadata["actor_role"])
			}
			for _, k := range []string{"scope", "email", "user_id", "session_id", "client_secret", "token"} {
				if _, ok := e.Metadata[k]; ok {
					t.Errorf("scope.denied leaked %q", k)
				}
			}
		}
	}
	if !sawScope {
		t.Errorf("missing scope.denied event; events=%+v", eng.rec.Events())
	}
}

// AssignRole over the live engine rejects a cross-org target
// user with 403, fires no SessionRevoker, and emits no
// org_role.assigned audit. Pins the service-layer target-user
// tenant guard at the HTTP boundary.
func TestRBAC_AssignRoleCrossOrgTargetRejected(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{Role: domain.RoleSiteAdmin, UserID: uuid.New(), OrganizationID: org}
	repo := newMemOrgRoleRepo()
	userRepo := newMemUserRepo()
	revoker := &service.RecorderSessionRevoker{}
	rec := &audit.Recorder{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	RegisterRBACRoutes(r, RBACHandlerDeps{
		OrgRoleService: service.NewOrgRoleService(nil, repo, nil).
			WithUserRepository(userRepo).
			WithSessionRevoker(revoker),
		Audit:       rec,
		FeatureGate: features.OpenGate{},
	})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = repo.Create(context.Background(), role)
	target := uuid.New()
	// Target lives in a DIFFERENT org from the role.
	_, _ = userRepo.Create(context.Background(), &domain.User{
		ID: target, OrganizationID: uuid.New(), Email: "u@test", Role: domain.RoleOrgUser, PasswordHash: "h",
	})
	body := bytes.NewBufferString(`{"role_id":"` + role.ID.String() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target.String()+"/roles", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", w.Code, w.Body.String())
	}
	if len(revoker.Calls()) != 0 {
		t.Errorf("revoker fired on rejected assignment: %+v", revoker.Calls())
	}
	for _, e := range rec.Events() {
		if e.Action == "org_role.assigned" {
			t.Errorf("rejected assignment emitted org_role.assigned audit: %+v", e)
		}
	}
}

// AssignRoleToUser fires the revoker for the target user with
// reason rbac_role_assigned. Mirrors monolith §2.8.
func TestRBAC_AssignRoleFiresRevokeForTarget(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: org, Scope: "orgs:update"}
	repo := newMemOrgRoleRepo()
	userRepo := newMemUserRepo()
	revoker := &service.RecorderSessionRevoker{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	RegisterRBACRoutes(r, RBACHandlerDeps{
		OrgRoleService: service.NewOrgRoleService(nil, repo, nil).
			WithUserRepository(userRepo).
			WithSessionRevoker(revoker),
		Audit:       &audit.Recorder{},
		FeatureGate: features.OpenGate{},
	})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = repo.Create(context.Background(), role)
	target := uuid.New()
	_, _ = userRepo.Create(context.Background(), &domain.User{
		ID: target, OrganizationID: org, Email: "u@test", Role: domain.RoleOrgUser, PasswordHash: "h",
	})
	body := bytes.NewBufferString(`{"role_id":"` + role.ID.String() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target.String()+"/roles", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("assign status = %d, body=%q", w.Code, w.Body.String())
	}
	calls := revoker.Calls()
	if len(calls) != 1 || calls[0].UserID != target || calls[0].Reason != "rbac_role_assigned" {
		t.Errorf("revoker calls = %+v, want one rbac_role_assigned for target", calls)
	}
}

// ---------- Revocation hook fires on Delete via the live engine ----------

func TestRBAC_DeleteRoleFiresSessionRevokeHook(t *testing.T) {
	org := uuid.New()
	p := &domain.Principal{Role: domain.RoleOrgAdmin, UserID: uuid.New(), OrganizationID: org, Scope: "orgs:update"}
	eng := newRBACEngine(t, p, features.OpenGate{})
	// Build the service with a recorder hooked in.
	repo := newMemOrgRoleRepo()
	revoker := &service.RecorderSessionRevoker{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	RegisterRBACRoutes(r, RBACHandlerDeps{
		OrgRoleService: service.NewOrgRoleService(nil, repo, nil).WithSessionRevoker(revoker),
		Audit:          &audit.Recorder{},
		FeatureGate:    features.OpenGate{},
	})
	role := &domain.OrgRole{ID: uuid.New(), OrgID: org, Name: "X"}
	_ = repo.Create(context.Background(), role)
	holder := uuid.New()
	_ = repo.AssignRoleToUser(context.Background(), holder, role.ID, p.UserID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/organizations/"+org.String()+"/roles/"+role.ID.String(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%q", w.Code, w.Body.String())
	}
	if calls := revoker.Calls(); len(calls) != 1 || calls[0].UserID != holder || calls[0].Reason != "rbac_role_deleted" {
		t.Errorf("revoker calls = %+v, want 1 call for holder with rbac_role_deleted", calls)
	}
	_ = eng
}
