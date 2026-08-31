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

// THE-UNVALIDATED-REST (2026-08-31): HandleUpdateOrganization collapsed every
// error that was not the invalid-field sentinel into 404. The service refuses
// a rename of the SYSTEM organization with domain.ErrForbidden
// (AdminPermissionsModel.md: "System organization CANNOT be deleted and
// renamed"), so site_admin was told that a row it can plainly read does not
// exist — the same lying status that was just removed for invalid input, one
// line below it.
//
// The proof runs the REAL handler over the REAL service with a recording
// repository, so it fails if the mapping is removed OR if the service stops
// refusing. Asserting on the sentinel alone would survive both.
//
// RULE: ORG-SYSTEM-RENAME-FORBIDDEN-1
func TestOrganizationUpdateStatus_RefusalIsForbiddenNotNotFound(t *testing.T) {
	systemID := uuid.MustParse(domain.SystemOrgID)

	newFixture := func() (*wireOrgRepo, OrganizationsHandlerDeps) {
		repo := &wireOrgRepo{memOrgRepo: newMemOrgRepo()}
		_, _ = repo.memOrgRepo.Create(context.Background(), &domain.Organization{
			ID:     systemID,
			Name:   "System",
			Domain: "system.local",
			Active: true,
		})
		return repo, OrganizationsHandlerDeps{
			Audit:               audit.NoopService{},
			OrganizationService: service.NewOrganizationService(nil, repo),
		}
	}

	// ── THE DEFECT: a refusal must not be reported as a miss ──
	repo, deps := newFixture()
	code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+systemID.String(),
		`{"name":"Renamed System"}`, HandleUpdateOrganization(deps))
	if code == http.StatusNotFound {
		t.Fatalf("renaming the System organization answered 404 — a refusal reported as a missing row")
	}
	if code != http.StatusForbidden {
		t.Fatalf("renaming the System organization answered %d, want 403", code)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("the refused rename still reached the repository %d time(s)", repo.updateCalls)
	}

	// ── the three answers must stay DISTINGUISHABLE from one another; a
	// handler that answered 403 for everything would pass the case above ──
	_, deps = newFixture()
	if code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+uuid.New().String(),
		`{"name":"Ghost"}`, HandleUpdateOrganization(deps)); code != http.StatusNotFound {
		t.Errorf("a genuinely absent organization answered %d, want 404", code)
	}
	_, deps = newFixture()
	if code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+systemID.String(),
		`{"domain":"lexus"}`, HandleUpdateOrganization(deps)); code != http.StatusBadRequest {
		t.Errorf("an invalid field answered %d, want 400", code)
	}

	// ── and a legitimate change to a NON-system organization still lands ──
	repo, deps = newFixture()
	tenant := uuid.New()
	_, _ = repo.memOrgRepo.Create(context.Background(), &domain.Organization{
		ID: tenant, Name: "Acme", Domain: "acme.test", Active: true,
	})
	if code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+tenant.String(),
		`{"name":"Acme Renamed"}`, HandleUpdateOrganization(deps)); code != http.StatusOK {
		t.Errorf("renaming a tenant organization answered %d, want 200", code)
	}

	// The System organization may still be updated in ways that are NOT a
	// rename — the refusal is about the name, not about the row.
	repo, deps = newFixture()
	if code := runHandler(t, http.MethodPut, "/o/:id", "/o/"+systemID.String(),
		`{"max_sessions_per_user":5}`, HandleUpdateOrganization(deps)); code != http.StatusOK {
		t.Errorf("a non-rename update of the System organization answered %d, want 200", code)
	}
	if repo.updateCalls != 1 {
		t.Errorf("the accepted update reached the repository %d time(s), want 1", repo.updateCalls)
	}
}

var _ repository.OrganizationRepository = (*wireOrgRepo)(nil)
