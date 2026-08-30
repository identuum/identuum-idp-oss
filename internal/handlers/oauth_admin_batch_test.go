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
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// fakeClientRepo implements repository.ClientRepository with only
// the methods the OSS handler reads from. Unimplemented methods
// panic so accidental new dependencies surface as test failures.
type fakeClientRepo struct {
	list []*domain.Client
	byID *domain.Client
}

func (f *fakeClientRepo) RegisterClient(_ context.Context, _ *domain.Client) error {
	panic("not used")
}
func (f *fakeClientRepo) GetClientByID(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
	if f.byID == nil {
		return nil, nil
	}
	return f.byID, nil
}
func (f *fakeClientRepo) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	panic("not used")
}
func (f *fakeClientRepo) Update(_ context.Context, _ *domain.Client) error { panic("not used") }
func (f *fakeClientRepo) Delete(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
	panic("not used")
}
func (f *fakeClientRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.Client, int, error) {
	return f.list, len(f.list), nil
}
func (f *fakeClientRepo) ListByServiceAccountID(_ context.Context, _, _ uuid.UUID) ([]*domain.Client, error) {
	panic("not used")
}
func (f *fakeClientRepo) SaveConsent(_ context.Context, _ *domain.Consent) error { panic("not used") }
func (f *fakeClientRepo) GetConsent(_ context.Context, _, _ uuid.UUID, _ *uuid.UUID) (*domain.Consent, error) {
	panic("not used")
}

// fakeAPIResourceRepo
type fakeAPIResourceRepo struct {
	list []*domain.APIResource
	byID *domain.APIResource
}

func (f *fakeAPIResourceRepo) Create(_ context.Context, _ *domain.APIResource, _ []domain.APIScope) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) GetByID(_ context.Context, _ uuid.UUID, _ *uuid.UUID) (*domain.APIResource, error) {
	if f.byID == nil {
		return nil, nil
	}
	return f.byID, nil
}
func (f *fakeAPIResourceRepo) GetByAudienceGlobal(_ context.Context, _ string) (*domain.APIResource, error) {
	panic("not used")
}
func (f *fakeAPIResourceRepo) Update(_ context.Context, _ *domain.APIResource) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) Delete(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.APIResource, int, error) {
	return f.list, len(f.list), nil
}
func (f *fakeAPIResourceRepo) AddScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) RemoveScope(_ context.Context, _, _ uuid.UUID) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) ReplaceScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	panic("not used")
}
func (f *fakeAPIResourceRepo) UpdateWithScopes(_ context.Context, _ *domain.APIResource, _ []domain.APIScope) error {
	panic("not used")
}

// fakeScopeTemplateRepo
type fakeScopeTemplateRepo struct {
	list []*domain.ScopeTemplate
	byID *domain.ScopeTemplate
}

func (f *fakeScopeTemplateRepo) Create(_ context.Context, _ *domain.ScopeTemplate) error {
	panic("not used")
}
func (f *fakeScopeTemplateRepo) GetByID(_ context.Context, _, _ uuid.UUID) (*domain.ScopeTemplate, error) {
	if f.byID == nil {
		return nil, nil
	}
	return f.byID, nil
}
func (f *fakeScopeTemplateRepo) List(_ context.Context, _ uuid.UUID) ([]*domain.ScopeTemplate, error) {
	return f.list, nil
}
func (f *fakeScopeTemplateRepo) Update(_ context.Context, _ *domain.ScopeTemplate) error {
	panic("not used")
}
func (f *fakeScopeTemplateRepo) Delete(_ context.Context, _, _ uuid.UUID) error { panic("not used") }

func batchEngine(t *testing.T, with func(r *gin.Engine), principal *domain.Principal) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	with(r)
	return r
}

// ----- Clients --------------------------------------------------

func TestClients_ListOmitsSecretHash(t *testing.T) {
	// THE-CLIENTS-GUARD: the surface is org_admin's own — the list principal
	// flipped with the guard; site_admin is refused (403) now.
	orgID := uuid.New()
	repo := &fakeClientRepo{
		list: []*domain.Client{{
			ID:               uuid.New(),
			ClientID:         "cli-1",
			Name:             "Example Client",
			OrganizationID:   &orgID,
			ClientSecretHash: "SECRET-HASH-MUST-NOT-LEAK",
			Scope:            "openid email",
			RedirectURIs:     []string{"https://example.com/cb"},
			CreatedAt:        time.Now().UTC(),
			UpdatedAt:        time.Now().UTC(),
		}},
	}
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterClientsRoutes(r, ClientsHandlerDeps{ClientRepo: repo, Audit: audit.NoopService{}})
	}, orgAdminClientPrincipal(orgID))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "SECRET-HASH-MUST-NOT-LEAK") {
		t.Errorf("body leaked client secret hash: %q", body)
	}
	if strings.Contains(body, `"client_secret_hash"`) || strings.Contains(body, `"client_secret"`) {
		t.Errorf("body contains secret-bearing field name: %q", body)
	}
	if !strings.Contains(body, `"client_id":"cli-1"`) {
		t.Errorf("body missing expected client_id: %q", body)
	}
}

func TestClients_UnauthenticatedReturns401(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterClientsRoutes(r, ClientsHandlerDeps{ClientRepo: &fakeClientRepo{}})
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestClients_NonSiteAdminReturns403(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterClientsRoutes(r, ClientsHandlerDeps{ClientRepo: &fakeClientRepo{}})
	}, &domain.Principal{Role: domain.RoleOrgAdmin})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestClients_MutationsReturn501(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterClientsRoutes(r, ClientsHandlerDeps{ClientRepo: &fakeClientRepo{}})
	}, siteAdminPrincipal())
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/clients"},
		{http.MethodPut, "/api/v1/clients/" + uuid.NewString()},
		{http.MethodDelete, "/api/v1/clients/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/clients/" + uuid.NewString() + "/secret/regenerate"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s status = %d, want 501", c.method, c.path, rec.Code)
		}
	}
}

// ----- API Resources --------------------------------------------

// orgAdminBatchPrincipal builds the org_admin actor the reworked
// api-resources surface requires (THE-INVERTED-GUARD).
func orgAdminBatchPrincipal(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Email:          "org-admin@example.test",
		Role:           domain.RoleOrgAdmin,
	}
}

// orgAdminClientPrincipal is orgAdminBatchPrincipal carrying the role-derived
// clients:* session scopes, which the clients scope guard requires
// (THE-CLIENTS-GUARD: the surface is the org's own org_admin's, never
// site_admin's).
func orgAdminClientPrincipal(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Email:          "org-admin@example.test",
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}
}

func TestAPIResources_ListOmitsSecretHash(t *testing.T) {
	// THE-INVERTED-GUARD: the surface is org_admin's (its own org), never
	// site_admin's — the list principal flipped with the guard.
	orgID := uuid.New()
	repo := &fakeAPIResourceRepo{
		list: []*domain.APIResource{{
			ID:                 uuid.New(),
			OrganizationID:     orgID,
			Name:               "API Resource",
			Audience:           "https://api.example.com",
			Active:             true,
			TokenTTLSecs:       3600,
			ResourceSecretHash: "RESOURCE-HASH-MUST-NOT-LEAK",
			Scopes:             []domain.APIScope{{Name: "read", Description: "Read access"}},
			CreatedAt:          time.Now().UTC(),
			UpdatedAt:          time.Now().UTC(),
		}},
	}
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{APIResourceRepo: repo})
	}, orgAdminBatchPrincipal(orgID))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-resources", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "RESOURCE-HASH-MUST-NOT-LEAK") {
		t.Errorf("body leaked resource secret hash: %q", body)
	}
	if strings.Contains(body, `"resource_secret_hash"`) {
		t.Errorf("body contains secret-bearing field name: %q", body)
	}
	if !strings.Contains(body, `"audience":"https://api.example.com"`) {
		t.Errorf("body missing audience: %q", body)
	}
}

func TestAPIResources_UnauthenticatedReturns401(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{APIResourceRepo: &fakeAPIResourceRepo{}})
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-resources", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAPIResources_MutationsReturn501(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{APIResourceRepo: &fakeAPIResourceRepo{}})
	}, siteAdminPrincipal())
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/api-resources"},
		{http.MethodPut, "/api/v1/api-resources/" + uuid.NewString()},
		{http.MethodDelete, "/api/v1/api-resources/" + uuid.NewString()},
		{http.MethodPost, "/api/v1/api-resources/" + uuid.NewString() + "/secret/regenerate"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s status = %d, want 501", c.method, c.path, rec.Code)
		}
	}
}

// ----- Scope Templates ------------------------------------------

func TestScopeTemplates_ListReturnsSafeShape(t *testing.T) {
	orgID := uuid.New()
	repo := &fakeScopeTemplateRepo{
		list: []*domain.ScopeTemplate{{
			ID:             uuid.New(),
			OrganizationID: orgID,
			Name:           "Admin Template",
			Description:    "Full admin",
			Scopes:         []string{"org:read", "org:write"},
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}},
	}
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterScopeTemplatesRoutes(r, ScopeTemplatesHandlerDeps{ScopeTemplateRepo: repo})
	}, &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleSiteAdmin})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scope-templates", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body struct {
		ScopeTemplates []struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		} `json:"scope_templates"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Count != 1 || body.ScopeTemplates[0].Name != "Admin Template" {
		t.Errorf("unexpected body: %+v", body)
	}
}

func TestScopeTemplates_MissingOrgContext400(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterScopeTemplatesRoutes(r, ScopeTemplatesHandlerDeps{ScopeTemplateRepo: &fakeScopeTemplateRepo{}})
	}, &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}) // no OrganizationID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scope-templates", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestScopeTemplates_MutationsReturn501(t *testing.T) {
	r := batchEngine(t, func(r *gin.Engine) {
		RegisterScopeTemplatesRoutes(r, ScopeTemplatesHandlerDeps{ScopeTemplateRepo: &fakeScopeTemplateRepo{}})
	}, &domain.Principal{UserID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleSiteAdmin})
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/scope-templates"},
		{http.MethodPut, "/api/v1/scope-templates/" + uuid.NewString()},
		{http.MethodDelete, "/api/v1/scope-templates/" + uuid.NewString()},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s status = %d, want 501", c.method, c.path, rec.Code)
		}
	}
}
