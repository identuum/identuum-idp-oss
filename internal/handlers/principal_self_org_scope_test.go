package handlers

import (
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

// selfScopeEngine wires the users + organizations + domains groups
// plus the new /profile route. It exposes a callback for the test to
// seed the in-memory repos before issuing the request.
type selfScopeEngine struct {
	r          *gin.Engine
	userRepo   *memUserRepo
	orgRepo    *memOrgRepo
	domainRepo *memOrgDomainRepo
	rec        *audit.Recorder
}

func newSelfScopeEngine(t *testing.T, principal *domain.Principal) selfScopeEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	userRepo := newMemUserRepo()
	orgRepo := newMemOrgRepo()
	domainRepo := newMemOrgDomainRepo()
	rec := &audit.Recorder{}
	userDeps := UsersHandlerDeps{
		UserService: service.NewUserService(nil, userRepo),
		Audit:       rec,
	}
	RegisterUsersRoutes(r, userDeps)
	RegisterProfileRoute(r, userDeps)
	RegisterOrganizationsRoutes(r, OrganizationsHandlerDeps{
		OrganizationService: service.NewOrganizationService(nil, orgRepo),
		Audit:               rec,
	})
	RegisterOrganizationDomainsRoutes(r, OrganizationDomainsHandlerDeps{
		OrganizationDomainService: service.NewOrganizationDomainService(nil, domainRepo, stubVerifier{err: nil}),
		Audit:                     rec,
	})
	return selfScopeEngine{r: r, userRepo: userRepo, orgRepo: orgRepo, domainRepo: domainRepo, rec: rec}
}

func seedUser(eng selfScopeEngine, p *domain.Principal) *domain.User {
	now := time.Now().UTC()
	u := &domain.User{
		ID:             p.UserID,
		OrganizationID: p.OrganizationID,
		Email:          p.Email,
		Role:           p.Role,
		PasswordHash:   "PASSWORD-HASH-SHOULD-NEVER-LEAK",
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, _ = eng.userRepo.Create(context.Background(), u)
	return u
}

func seedOrg(eng selfScopeEngine, id uuid.UUID, name string) *domain.Organization {
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

func reqJSON(t *testing.T, eng selfScopeEngine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// ---------- /api/v1/profile ----------

func TestProfile_Unauthenticated401(t *testing.T) {
	eng := newSelfScopeEngine(t, nil)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/profile")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestProfile_ReturnsSafeUser(t *testing.T) {
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "user@example.test",
		Role:           domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	seedUser(eng, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/profile")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "PASSWORD-HASH-SHOULD-NEVER-LEAK") {
		t.Errorf("profile leaked password hash")
	}
	for _, banned := range []string{`"password_hash"`, `"mfa_secret"`, `"mfa_recovery_codes"`, `"activation_token_hash"`, `"verification_token_hash"`} {
		if strings.Contains(body, banned) {
			t.Errorf("profile leaked sensitive field name %s", banned)
		}
	}
	var got safeUser
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != p.UserID {
		t.Errorf("profile id = %s, want %s", got.ID, p.UserID)
	}
}

func TestProfile_MissingUser404(t *testing.T) {
	p := &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/profile")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestProfile_PrincipalWithoutUserID401(t *testing.T) {
	p := &domain.Principal{
		Role: domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/profile")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// ---------- /api/v1/organizations/current ----------

func TestCurrentOrg_Unauthenticated401(t *testing.T) {
	eng := newSelfScopeEngine(t, nil)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/current")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestCurrentOrg_ReturnsSafeOrg(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgID, "Acme")
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/current")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var got safeOrganization
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != orgID {
		t.Errorf("returned org id = %s, want %s", got.ID, orgID)
	}
}

func TestCurrentOrg_NilOrgPrincipalReturns400(t *testing.T) {
	p := &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/current")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCurrentOrg_SiteAdminWithNoOrgReturns400AtHandler(t *testing.T) {
	// site_admin without org passes the guard but the handler still
	// returns 400 because /current is a self-route with no target.
	p := &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleSiteAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/current")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ---------- GET /api/v1/organizations/:id same-org org_admin ----------

func TestGetOrgByID_SameOrgAdminAllowed(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgID, "Acme")
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}

func TestGetOrgByID_CrossOrgAdminForbidden(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgA,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgB, "Other")
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgB.String())
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestGetOrgByID_OrgUserForbidden(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgID, "Acme")
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID.String())
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestGetOrgByID_SiteAdminAcrossOrgsAllowed(t *testing.T) {
	orgID := uuid.New()
	p := siteAdminPrincipal()
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgID, "Acme")
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID.String())
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// PUT /:id must still be site_admin-only (loosening was for GET only).
func TestPutOrgByID_SameOrgAdminForbidden(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	seedOrg(eng, orgID, "Acme")
	req := httptest.NewRequest(http.MethodPut, "/api/v1/organizations/"+orgID.String(), strings.NewReader(`{"name":"X"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// ---------- /api/v1/organizations/:id/domains same-org org_admin ----------

func TestOrgDomains_SameOrgAdminAllowed(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID.String()+"/domains")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
}

func TestOrgDomains_CrossOrgAdminForbidden(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgA,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgB.String()+"/domains")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestOrgDomains_OrgUserForbidden(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgUser,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/organizations/"+orgID.String()+"/domains")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// ---------- Users routes remain site_admin-only ----------

func TestUsers_OrgAdminStillForbidden(t *testing.T) {
	orgID := uuid.New()
	p := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
	eng := newSelfScopeEngine(t, p)
	rec := reqJSON(t, eng, http.MethodGet, "/api/v1/users")
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /users for org_admin = %d, want 403 (slice keeps users.* site_admin-only)", rec.Code)
	}
}
