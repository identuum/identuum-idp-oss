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

	// The policy fields are the organization's own org_admin's (owner ruling,
	// v0.9.5), so the binding is asserted as that actor; a site_admin sending
	// them for a tenant is refused before the repository is reached.
	t.Run("update binds the five repository-supported fields", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		body := `{"service_account_expiry_days":90,"m2m_anomaly_limit":50,"m2m_anomaly_window_seconds":300,"require_strict_reauth":true,"local_admin_only":true}`
		code := runHandlerActing(t, orgAdminOf(id, "orgs:update"), http.MethodPut, "/o/:id", "/o/"+id.String(), body, HandleUpdateOrganization(newDeps(repo)))
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

	t.Run("a site_admin sending those fields for a tenant is refused before any write", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"require_strict_reauth":true}`, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusForbidden {
			t.Fatalf("site_admin policy update status = %d, want 403", code)
		}
		if repo.updateCalls != 0 {
			t.Errorf("the refusal must happen before any repository write (calls=%d)", repo.updateCalls)
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

	t.Run("compliance_contact_email stays deliberately unbound (tenant-owned; no ruling writes it here)", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		id := seed(repo.memOrgRepo)
		code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+id.String(), `{"name":"Renamed","compliance_contact_email":"cc@acme.test"}`, HandleUpdateOrganization(newDeps(repo)))
		if code != http.StatusOK {
			t.Fatalf("update status = %d, want 200", code)
		}
		if repo.lastOpts.ComplianceContactEmail != nil {
			t.Errorf("compliance_contact_email must not be settable through this endpoint")
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

	// OSS-SA-EXPIRY-2 ruling e: a new organization starts at 0 (no default
	// service-account expiry) unless its create request names a value.
	t.Run("create without service_account_expiry_days starts the organization at 0", func(t *testing.T) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		code := runHandler(t, http.MethodPost, "/o", "/o", `{"name":"Quiet Start","domain":"quiet-start.test"}`, HandleCreateOrganization(newDeps(repo)))
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
		if created.ServiceAccountExpiryDays != 0 {
			t.Errorf("service_account_expiry_days = %d, want 0 (no default expiry until the org_admin turns it on)", created.ServiceAccountExpiryDays)
		}
	})
}
