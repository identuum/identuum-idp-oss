package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Fault wrappers: each embeds the family's mem repo and injects one
// write-path failure — the handler's error branch is the subject.
type faultAPIResourceRepo struct {
	*memAPIResourceRepo
	updateErr error
}

func (r *faultAPIResourceRepo) UpdateWithScopes(ctx context.Context, res *domain.APIResource, scopes []domain.APIScope) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	return r.memAPIResourceRepo.UpdateWithScopes(ctx, res, scopes)
}

func (r *faultAPIResourceRepo) Update(ctx context.Context, res *domain.APIResource) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	return r.memAPIResourceRepo.Update(ctx, res)
}

type faultScopeTemplateRepo struct {
	*memScopeTemplateRepo
	updateErr error
}

func (r *faultScopeTemplateRepo) Update(ctx context.Context, t *domain.ScopeTemplate) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	return r.memScopeTemplateRepo.Update(ctx, t)
}

type faultOrgRoleRepo struct {
	*memOrgRoleRepo
	updateErr error
}

func (r *faultOrgRoleRepo) Update(ctx context.Context, role *domain.OrgRole) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	return r.memOrgRoleRepo.Update(ctx, role)
}

type faultClientRepo struct {
	*memClientRepo
	deleteErr error
}

func (r *faultClientRepo) Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	return r.memClientRepo.Delete(ctx, id, orgID)
}

type faultOrgDomainRepo struct {
	*memOrgDomainRepo
	deleteErr error
}

func (r *faultOrgDomainRepo) DeleteOrganizationDomain(ctx context.Context, id, orgID uuid.UUID) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	return r.memOrgDomainRepo.DeleteOrganizationDomain(ctx, id, orgID)
}

// RULE: FAMILY-FALLBACK-1
func TestFiveFamilyFallbacksTellTheTruth(t *testing.T) {
	siteAdmin := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
	boom := errors.New("disk on fire")

	t.Run("api-resources update: miss 404, audience collision 409, unknown 500", func(t *testing.T) {
		// THE-INVERTED-GUARD: this family answers to the org's own
		// org_admin, never site_admin — the principal flipped with the
		// guard; the honest-refusal contract is unchanged.
		repo := &faultAPIResourceRepo{memAPIResourceRepo: newMemAPIResourceRepo()}
		deps := APIResourcesHandlerDeps{Audit: audit.NoopService{}, APIResourceService: service.NewAPIResourceService(nil, repo)}
		orgID := uuid.New()
		orgAdmin := orgAdminBatchPrincipal(orgID)
		res := &domain.APIResource{ID: uuid.New(), OrganizationID: orgID, Name: "r", Audience: "aud", TokenTTLSecs: 300}
		_ = repo.Create(context.Background(), res, nil)

		code, _ := honestRefusalCall(t, orgAdmin, http.MethodPut, "/r/:id", "/r/"+uuid.NewString(), `{"name":"x"}`, HandleUpdateAPIResource(deps))
		if code != http.StatusNotFound {
			t.Fatalf("miss = %d, want 404", code)
		}
		repo.updateErr = domain.ErrAPIResourceAlreadyExists
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPut, "/r/:id", "/r/"+res.ID.String(), `{"name":"collides"}`, HandleUpdateAPIResource(deps))
		if code != http.StatusConflict || body["error"] != "audience_exists" {
			t.Fatalf("collision = %d %v, want 409 audience_exists", code, body)
		}
		repo.updateErr = boom
		code, body = honestRefusalCall(t, orgAdmin, http.MethodPut, "/r/:id", "/r/"+res.ID.String(), `{"name":"y"}`, HandleUpdateAPIResource(deps))
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown = %d %v, want 500 internal_error (the old 404 lie)", code, body)
		}
	})

	t.Run("scope-templates update: miss 404, name collision 409, unknown 500", func(t *testing.T) {
		orgID := uuid.New()
		orgAdmin := &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
		repo := &faultScopeTemplateRepo{memScopeTemplateRepo: newMemScopeTemplateRepo()}
		deps := ScopeTemplatesHandlerDeps{Audit: audit.NoopService{}, ScopeTemplateService: service.NewScopeTemplateService(nil, repo)}
		tmpl := &domain.ScopeTemplate{ID: uuid.New(), OrganizationID: orgID, Name: "t"}
		_ = repo.Create(context.Background(), tmpl)

		code, _ := honestRefusalCall(t, orgAdmin, http.MethodPut, "/t/:id", "/t/"+uuid.NewString(), `{"name":"x"}`, HandleUpdateScopeTemplate(deps))
		if code != http.StatusNotFound {
			t.Fatalf("miss = %d, want 404", code)
		}
		repo.updateErr = domain.ErrScopeTemplateAlreadyExists
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPut, "/t/:id", "/t/"+tmpl.ID.String(), `{"name":"taken"}`, HandleUpdateScopeTemplate(deps))
		if code != http.StatusConflict || body["error"] != "name_exists" {
			t.Fatalf("collision = %d %v, want 409 name_exists", code, body)
		}
		repo.updateErr = boom
		code, body = honestRefusalCall(t, orgAdmin, http.MethodPut, "/t/:id", "/t/"+tmpl.ID.String(), `{"name":"y"}`, HandleUpdateScopeTemplate(deps))
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown = %d %v, want 500 internal_error", code, body)
		}
	})

	t.Run("rbac update: miss 404, name collision 409, unknown 500", func(t *testing.T) {
		repo := &faultOrgRoleRepo{memOrgRoleRepo: newMemOrgRoleRepo()}
		deps := RBACHandlerDeps{Audit: audit.NoopService{}, OrgRoleService: service.NewOrgRoleService(nil, repo, nil)}
		role := &domain.OrgRole{ID: uuid.New(), OrgID: uuid.New(), Name: "r"}
		_ = repo.Create(context.Background(), role)

		code, _ := honestRefusalCall(t, siteAdmin, http.MethodPut, "/role/:role_id", "/role/"+uuid.NewString(), `{"name":"x"}`, HandleUpdateOrgRole(deps))
		if code != http.StatusNotFound {
			t.Fatalf("miss = %d, want 404", code)
		}
		repo.updateErr = domain.ErrOrgRoleAlreadyExists
		code, body := honestRefusalCall(t, siteAdmin, http.MethodPut, "/role/:role_id", "/role/"+role.ID.String(), `{"name":"taken"}`, HandleUpdateOrgRole(deps))
		if code != http.StatusConflict || body["error"] != "name_exists" {
			t.Fatalf("collision = %d %v, want 409 name_exists", code, body)
		}
		repo.updateErr = boom
		code, body = honestRefusalCall(t, siteAdmin, http.MethodPut, "/role/:role_id", "/role/"+role.ID.String(), `{"name":"y"}`, HandleUpdateOrgRole(deps))
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown = %d %v, want 500 internal_error", code, body)
		}
	})

	t.Run("clients delete: idempotent miss stays 200, unknown fault is 500 not a 404 lie", func(t *testing.T) {
		repo := &faultClientRepo{memClientRepo: newMemClientRepo()}
		deps := ClientsHandlerDeps{Audit: audit.NoopService{}, ClientService: service.NewClientService(nil, repo)}
		code, _ := honestRefusalCall(t, siteAdmin, http.MethodDelete, "/c/:id", "/c/"+uuid.NewString(), "", HandleDeleteClient(deps))
		if code != http.StatusOK {
			t.Fatalf("idempotent miss = %d, want the documented 200", code)
		}
		repo.deleteErr = boom
		code, body := honestRefusalCall(t, siteAdmin, http.MethodDelete, "/c/:id", "/c/"+uuid.NewString(), "", HandleDeleteClient(deps))
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown = %d %v, want 500 internal_error (no 23505 path exists on delete — no invented 409)", code, body)
		}
	})

	t.Run("org-domains delete: sentinel miss 404, unknown 500", func(t *testing.T) {
		repo := &faultOrgDomainRepo{memOrgDomainRepo: newMemOrgDomainRepo()}
		deps := OrganizationDomainsHandlerDeps{Audit: audit.NoopService{}, OrganizationDomainService: service.NewOrganizationDomainService(nil, repo, nil)}
		orgID, domID := uuid.New(), uuid.New()
		repo.deleteErr = domain.ErrOrganizationDomainNotFound
		code, _ := honestRefusalCall(t, siteAdmin, http.MethodDelete, "/o/:id/d/:domain_id", "/o/"+orgID.String()+"/d/"+domID.String(), "", HandleDeleteOrganizationDomain(deps))
		if code != http.StatusNotFound {
			t.Fatalf("sentinel miss = %d, want 404", code)
		}
		repo.deleteErr = boom
		code, body := honestRefusalCall(t, siteAdmin, http.MethodDelete, "/o/:id/d/:domain_id", "/o/"+orgID.String()+"/d/"+domID.String(), "", HandleDeleteOrganizationDomain(deps))
		if code != http.StatusInternalServerError || body["error"] != "internal_error" {
			t.Fatalf("unknown = %d %v, want 500 internal_error", code, body)
		}
	})
}
