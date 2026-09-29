package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// adminViewOrgRepo mirrors the Postgres repository's two lookups: GetByID
// sees only active, undeleted organizations; GetByIDAdmin sees every row.
type adminViewOrgRepo struct {
	repository.AdminOrganizationRepository
	org *domain.Organization
}

func (r adminViewOrgRepo) GetByID(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	if r.org == nil || !r.org.Active || r.org.DeletedAt != nil {
		return nil, domain.ErrOrganizationNotFound
	}
	return r.org, nil
}

func (r adminViewOrgRepo) GetByIDAdmin(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	if r.org == nil {
		return nil, domain.ErrOrganizationNotFound
	}
	return r.org, nil
}

// OSS-POLISH item 6 (ORG-RESTORE-1): a restored organization comes back
// inactive, and its detail page reads it (the active-agnostic admin view),
// but GET /:id/admin-recovery-candidates used the active-only lookup and
// answered 404, so the recovery panel said "Organization not found". It now
// reads the same admin view: an inactive org lists its org_admins; a
// soft-deleted org keeps its 404 (ORG-RESTORE-1's contract).
func TestOrgAdminRecovery_InactiveOrgListsItsAdmins_DeletedStays404(t *testing.T) {
	orgID := uuid.New()
	inactive := &domain.Organization{ID: orgID, Active: false}
	r := newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: adminViewOrgRepo{org: inactive},
		MemberLister:     stubAdminRecMemberLister{users: adminRecTestUsers(orgID)},
	})
	rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates")
	if rec.Code != http.StatusOK {
		t.Fatalf("inactive (restored) org: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp orgAdminRecoveryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Admins) != 1 || resp.Admins[0].Email != "admin@tenant.test" {
		t.Fatalf("admins = %+v, want the one org_admin", resp.Admins)
	}

	deletedAt := time.Now()
	deleted := &domain.Organization{ID: orgID, Active: false, DeletedAt: &deletedAt}
	r = newAdminRecEngine(t, siteAdminPrincipal(), OrganizationsHandlerDeps{
		OrganizationRepo: adminViewOrgRepo{org: deleted},
		MemberLister:     stubAdminRecMemberLister{users: adminRecTestUsers(orgID)},
	})
	if rec := doAdminRecGET(t, r, "/api/v1/organizations/"+orgID.String()+"/admin-recovery-candidates"); rec.Code != http.StatusNotFound {
		t.Fatalf("soft-deleted org: status = %d, want 404 (ORG-RESTORE-1)", rec.Code)
	}
}
