package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// wireOrgRepo records the Options that reach the repository — the seam
// this contract lives at: the repo's dynamic UPDATE already writes all
// seventeen option fields, so the handler's wire→Options translation is
// the whole defect surface (THE-INERT-ORG-FIELDS).
type wireOrgRepo struct {
	*memOrgRepo
	updateCalls int
	lastOpts    repository.UpdateOrganizationOptions
}

func (r *wireOrgRepo) Update(ctx context.Context, id uuid.UUID, opts repository.UpdateOrganizationOptions) (*domain.Organization, error) {
	r.updateCalls++
	r.lastOpts = opts
	return r.memOrgRepo.Update(ctx, id, opts)
}

// RULE: ORG-FIELDS-WIRE-1
func TestOrganizationFieldsWireContract(t *testing.T) {
	newDeps := func(repo repository.OrganizationRepository) OrganizationsHandlerDeps {
		return OrganizationsHandlerDeps{
			Audit:               audit.NoopService{},
			OrganizationService: service.NewOrganizationService(nil, repo),
		}
	}
	seed := func(repo *memOrgRepo) uuid.UUID {
		id := uuid.New()
		_, _ = repo.Create(context.Background(), &domain.Organization{ID: id, Name: "Acme", Active: true})
		return id
	}

	t.Run("update binds the five repository-supported fields", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		body := `{"service_account_expiry_days":90,"m2m_anomaly_limit":50,"m2m_anomaly_window_seconds":300,"require_strict_reauth":true,"local_admin_only":true}`
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), body, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusOK {
			t.Fatalf("update status = %d, want 200", code)
		}
		o := repo.lastOpts
		if o.ServiceAccountExpiryDays == nil || *o.ServiceAccountExpiryDays != 90 {
			t.Errorf("service_account_expiry_days did not reach the repository (silent drop)")
		}
		if o.M2MAnomalyLimit == nil || *o.M2MAnomalyLimit != 50 {
			t.Errorf("m2m_anomaly_limit did not reach the repository (silent drop)")
		}
		if o.M2MAnomalyWindowSeconds == nil || *o.M2MAnomalyWindowSeconds != 300 {
			t.Errorf("m2m_anomaly_window_seconds did not reach the repository (silent drop)")
		}
		if o.RequireStrictReauth == nil || !*o.RequireStrictReauth {
			t.Errorf("require_strict_reauth did not reach the repository (silent drop)")
		}
		if o.LocalAdminOnly == nil || !*o.LocalAdminOnly {
			t.Errorf("local_admin_only did not reach the repository (silent drop)")
		}
	})

	t.Run("update refuses slug loudly — org_slug is create-only", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"slug":"stolen-slug"}`, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusBadRequest {
			t.Fatalf("slug update status = %d, want a LOUD 400", code)
		}
		if repo.updateCalls != 0 {
			t.Errorf("slug refusal must happen before any repository write (calls=%d)", repo.updateCalls)
		}
	})

	t.Run("update refuses tier loudly — licensing is never client-settable", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"tier":"TierEnterprise"}`, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusBadRequest {
			t.Fatalf("tier update status = %d, want a LOUD 400 (security property)", code)
		}
		if repo.updateCalls != 0 {
			t.Errorf("tier refusal must happen before any repository write (calls=%d)", repo.updateCalls)
		}
	})

	t.Run("compliance_contact_email stays deliberately unbound (tenant-owned; endpoint is site_admin-only)", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"name":"Renamed","compliance_contact_email":"cc@acme.test"}`, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusOK {
			t.Fatalf("update status = %d, want 200", code)
		}
		if repo.lastOpts.ComplianceContactEmail != nil {
			t.Errorf("compliance_contact_email must not be settable on the site_admin infra endpoint")
		}
	})

	t.Run("create binds the four monolith fields and honors a custom slug", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		body := `{"name":"Born Loud","domain":"born-loud.test","slug":"born-loud-custom","allow_public_registration":true,"require_registration_approval":true,"require_strict_reauth":true,"service_account_expiry_days":30}`
		code := runHandler(t, http.MethodPost, "/o", "/o", body, HandleCreateOrganization(newDeps(repo)))
		if code != http.StatusCreated {
			t.Fatalf("create status = %d, want 201", code)
		}
		var created *domain.Organization
		repo.mu.Lock()
		for _, o := range repo.rows {
			created = o
		}
		repo.mu.Unlock()
		if created == nil {
			t.Fatal("no organization persisted")
		}
		if created.OrgSlug != "born-loud-custom" {
			t.Errorf("slug = %q, want the custom create-time slug", created.OrgSlug)
		}
		if !created.AllowPublicRegistration || !created.RequireRegistrationApproval || !created.RequireStrictReauth {
			t.Errorf("create dropped a bound bool: apr=%t rra=%t rsr=%t", created.AllowPublicRegistration, created.RequireRegistrationApproval, created.RequireStrictReauth)
		}
		if created.ServiceAccountExpiryDays != 30 {
			t.Errorf("service_account_expiry_days = %d, want 30", created.ServiceAccountExpiryDays)
		}
	})
}
