package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// adminFakeSARepo extends the lookup-only fake from
// service_account_service_test.go with the admin-method shapes
// the new code touches.
type adminFakeSARepo struct {
	*inMemoryServiceAccountRepo
	createErr error
}

func newAdminFakeSARepo() *adminFakeSARepo {
	return &adminFakeSARepo{inMemoryServiceAccountRepo: newInMemorySARepo()}
}

func (r *adminFakeSARepo) Create(_ context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	if r.createErr != nil {
		return nil, r.createErr
	}
	if sa.ID == uuid.Nil {
		sa.ID = uuid.New()
	}
	cp := *sa
	r.byID[sa.ID] = &cp
	return &cp, nil
}

func (r *adminFakeSARepo) ListByOrganization(_ context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	out := make([]*domain.ServiceAccount, 0)
	for _, v := range r.byID {
		if v.OrganizationID == orgID {
			cp := *v
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *adminFakeSARepo) Update(_ context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	cp := *sa
	r.byID[sa.ID] = &cp
	return &cp, nil
}

func (r *adminFakeSARepo) UpdateActive(_ context.Context, id, orgID uuid.UUID, active bool) error {
	v, ok := r.byID[id]
	if !ok || v.OrganizationID != orgID {
		return errors.New("not found")
	}
	v.Active = active
	return nil
}

func (r *adminFakeSARepo) Delete(_ context.Context, id, orgID uuid.UUID) error {
	v, ok := r.byID[id]
	if !ok || v.OrganizationID != orgID {
		return errors.New("not found")
	}
	delete(r.byID, id)
	return nil
}

// ---------- helpers ----------

func newSiteAdmin() *domain.Principal {
	return &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleSiteAdmin,
	}
}

func newOrgAdmin(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}
}

func newOrgUser(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgUser,
	}
}

func newAdminSAService() (*ServiceAccountService, *adminFakeSARepo) {
	repo := newAdminFakeSARepo()
	return NewServiceAccountService(nil, repo), repo
}

// ---------- CreateForActor ----------

func TestCreateForActor_OrgUserForbidden(t *testing.T) {
	svc, _ := newAdminSAService()
	orgID := uuid.New()
	_, err := svc.CreateForActor(context.Background(), newOrgUser(orgID), orgID, ServiceAccountAdminInput{Name: "ci"})
	if !errors.Is(err, ErrSAForbidden) {
		t.Errorf("err = %v", err)
	}
}

func TestCreateForActor_OrgAdminCrossOrgNotFound(t *testing.T) {
	svc, _ := newAdminSAService()
	other := uuid.New()
	_, err := svc.CreateForActor(context.Background(), newOrgAdmin(uuid.New()), other, ServiceAccountAdminInput{Name: "ci"})
	if !errors.Is(err, ErrSANotFound) {
		t.Errorf("err = %v", err)
	}
}

// THE-REMAINING-FOUR (2026-08-30): site_admin is REFUSED on tenant service
// accounts now — the model forbids the superuser from managing a tenant's own
// resources. The old "SiteAdminAnyOrgPasses" contract was the defect.
func TestCreateForActor_SiteAdminRefused(t *testing.T) {
	svc, _ := newAdminSAService()
	_, err := svc.CreateForActor(context.Background(), newSiteAdmin(), uuid.New(), ServiceAccountAdminInput{
		Name: "deploy-bot", Role: domain.RoleOrgUser,
	})
	if !errors.Is(err, ErrSAForbidden) {
		t.Fatalf("site_admin create must be ErrSAForbidden, got %v", err)
	}
}

// THE-REMAINING-FOUR: validation tests drive as a same-org org_admin now
// (site_admin is refused before validation runs).
func TestCreateForActor_EmptyNameRejected(t *testing.T) {
	svc, _ := newAdminSAService()
	org := uuid.New()
	_, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{Name: "  "})
	if !errors.Is(err, ErrSAInvalidInput) {
		t.Errorf("err = %v", err)
	}
}

func TestCreateForActor_DisallowedRoleRejected(t *testing.T) {
	svc, _ := newAdminSAService()
	org := uuid.New()
	_, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{
		Name: "bad", Role: domain.RoleSiteAdmin,
	})
	if !errors.Is(err, ErrSARoleInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestCreateForActor_ExpiryInPastRejected(t *testing.T) {
	svc, _ := newAdminSAService()
	org := uuid.New()
	past := time.Now().Add(-time.Hour)
	_, err := svc.CreateForActor(context.Background(), newOrgAdmin(org), org, ServiceAccountAdminInput{
		Name: "expired", ExpiresAt: &past,
	})
	if !errors.Is(err, ErrSAExpiryInvalid) {
		t.Errorf("err = %v", err)
	}
}

// ---------- GetForActor ----------

func TestGetForActor_OrgAdminCrossOrgNotFound(t *testing.T) {
	svc, repo := newAdminSAService()
	target := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: uuid.New(), Active: true, Role: domain.RoleOrgUser}
	repo.byID[target.ID] = target
	_, err := svc.GetForActor(context.Background(), newOrgAdmin(uuid.New()), target.ID)
	if !errors.Is(err, ErrSANotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestGetForActor_UnknownNotFound(t *testing.T) {
	svc, _ := newAdminSAService()
	_, err := svc.GetForActor(context.Background(), newOrgAdmin(uuid.New()), uuid.New())
	if !errors.Is(err, ErrSANotFound) {
		t.Errorf("err = %v", err)
	}
}

// ---------- UpdateForActor ----------

func TestUpdateForActor_AppliesPatchSafely(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{
		ID: saID, OrganizationID: orgID, Active: true, Role: domain.RoleOrgUser, Name: "ci",
	}
	newName, newRole := "ci-v2", domain.RoleOrgAdmin
	updated, err := svc.UpdateForActor(context.Background(), newOrgAdmin(orgID), saID, ServiceAccountUpdateInput{
		Name: &newName, Role: &newRole,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "ci-v2" || updated.Role != domain.RoleOrgAdmin {
		t.Errorf("update did not apply: %+v", updated)
	}
}

func TestUpdateForActor_RoleInvalidRejected(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: orgID, Active: true, Role: domain.RoleOrgUser}
	badRole := domain.RoleSiteAdmin
	_, err := svc.UpdateForActor(context.Background(), newOrgAdmin(orgID), saID, ServiceAccountUpdateInput{
		Role: &badRole,
	})
	if !errors.Is(err, ErrSARoleInvalid) {
		t.Errorf("err = %v", err)
	}
}

// ---------- SetActiveForActor ----------

func TestSetActive_DisableFlowFlipsFlag(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: orgID, Active: true, Role: domain.RoleOrgUser}
	if err := svc.SetActiveForActor(context.Background(), newOrgAdmin(orgID), saID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if repo.byID[saID].Active {
		t.Errorf("active still true")
	}
}

// ---------- DeleteForActor ----------

func TestDeleteForActor_OrgUserForbidden(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: orgID, Active: true, Role: domain.RoleOrgUser}
	if err := svc.DeleteForActor(context.Background(), newOrgUser(orgID), saID); !errors.Is(err, ErrSAForbidden) {
		t.Errorf("err = %v", err)
	}
}

// ---------- ListForActor ----------

func TestListForActor_OrgAdminOnlySeesOwnOrg(t *testing.T) {
	svc, repo := newAdminSAService()
	orgA, orgB := uuid.New(), uuid.New()
	repo.byID[uuid.New()] = &domain.ServiceAccount{ID: uuid.New(), OrganizationID: orgA, Active: true, Role: domain.RoleOrgUser}
	repo.byID[uuid.New()] = &domain.ServiceAccount{ID: uuid.New(), OrganizationID: orgB, Active: true, Role: domain.RoleOrgUser}
	got, err := svc.ListForActor(context.Background(), newOrgAdmin(orgA), orgA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, sa := range got {
		if sa.OrganizationID != orgA {
			t.Errorf("cross-org sa leaked: %s", sa.OrganizationID)
		}
	}
	_, err = svc.ListForActor(context.Background(), newOrgAdmin(orgA), orgB)
	if !errors.Is(err, ErrSANotFound) {
		t.Errorf("cross-org list err = %v", err)
	}
}

// ---------- ValidateBindingForClient ----------

func TestValidateBinding_NilIDIsUnbound(t *testing.T) {
	svc, _ := newAdminSAService()
	if err := svc.ValidateBindingForClient(context.Background(), uuid.Nil, nil); !errors.Is(err, ErrServiceAccountUnbound) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateBinding_ActiveSAOK(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: orgID, Active: true, Role: domain.RoleOrgUser}
	if err := svc.ValidateBindingForClient(context.Background(), saID, &orgID); err != nil {
		t.Errorf("active OK err = %v", err)
	}
}

func TestValidateBinding_CrossOrgRejected(t *testing.T) {
	svc, repo := newAdminSAService()
	other := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: other, Active: true, Role: domain.RoleOrgUser}
	clientOrg := uuid.New()
	err := svc.ValidateBindingForClient(context.Background(), saID, &clientOrg)
	if !errors.Is(err, ErrServiceAccountOrgMismatch) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateBinding_InactiveRejected(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	repo.byID[saID] = &domain.ServiceAccount{ID: saID, OrganizationID: orgID, Active: false, Role: domain.RoleOrgUser}
	if err := svc.ValidateBindingForClient(context.Background(), saID, &orgID); !errors.Is(err, ErrServiceAccountInactive) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateBinding_ExpiredRejected(t *testing.T) {
	svc, repo := newAdminSAService()
	orgID := uuid.New()
	saID := uuid.New()
	past := time.Now().Add(-time.Hour)
	repo.byID[saID] = &domain.ServiceAccount{
		ID: saID, OrganizationID: orgID, Active: true, ExpiresAt: &past, Role: domain.RoleOrgUser,
	}
	if err := svc.ValidateBindingForClient(context.Background(), saID, &orgID); !errors.Is(err, ErrServiceAccountExpired) {
		t.Errorf("err = %v", err)
	}
}
