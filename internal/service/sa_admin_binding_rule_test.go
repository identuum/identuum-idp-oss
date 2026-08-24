package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

type saBindRepo struct {
	repository.ServiceAccountRepository
	sa *domain.ServiceAccount
}

func (r saBindRepo) GetByID(context.Context, uuid.UUID) (*domain.ServiceAccount, error) {
	return r.sa, nil
}

// requireOrgAdmin authorizes a service-account admin action to site_admin OR the
// org_admin OF THE SAME organization; an org_admin of ANOTHER organization gets
// not-found (never a 403 that would confirm the org id exists), and an org_user
// is forbidden.
// RULE: SA-ADMIN-SCOPE-1
func TestRequireOrgAdmin_TenantScoped(t *testing.T) {
	s := &ServiceAccountService{}
	org := uuid.New()

	if err := s.requireOrgAdmin(&domain.Principal{Role: domain.RoleSiteAdmin}, org); err != nil {
		t.Errorf("site_admin must be allowed, got %v", err)
	}
	if err := s.requireOrgAdmin(&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org}, org); err != nil {
		t.Errorf("a same-org org_admin must be allowed, got %v", err)
	}
	if err := s.requireOrgAdmin(&domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: uuid.New()}, org); !errors.Is(err, ErrSANotFound) {
		t.Errorf("a cross-org org_admin must be NOT-FOUND (not 403), got %v", err)
	}
	if err := s.requireOrgAdmin(&domain.Principal{Role: domain.RoleOrgUser, OrganizationID: org}, org); !errors.Is(err, ErrSAForbidden) {
		t.Errorf("an org_user must be forbidden, got %v", err)
	}
}

// ValidateBindingForClient permits binding a service account to a client ONLY
// when the SA is in the client's OWN organization and is active + unexpired: a
// cross-org SA is ErrServiceAccountOrgMismatch, an inactive SA is
// ErrServiceAccountInactive, an expired SA is ErrServiceAccountExpired.
// RULE: SA-BINDING-ORG-1
func TestValidateBindingForClient_SameOrgActiveOnly(t *testing.T) {
	ctx := context.Background()
	saOrg := uuid.New()
	saID := uuid.New()
	mk := func(active bool, exp *time.Time) *ServiceAccountService {
		return NewServiceAccountService(nil, saBindRepo{sa: &domain.ServiceAccount{
			ID: saID, OrganizationID: saOrg, Active: active, ExpiresAt: exp,
		}})
	}

	if err := mk(true, nil).ValidateBindingForClient(ctx, saID, &saOrg); err != nil {
		t.Fatalf("a same-org active SA binding must be ok, got %v", err)
	}
	other := uuid.New()
	if err := mk(true, nil).ValidateBindingForClient(ctx, saID, &other); !errors.Is(err, ErrServiceAccountOrgMismatch) {
		t.Errorf("a cross-org binding must be ErrServiceAccountOrgMismatch, got %v", err)
	}
	if err := mk(false, nil).ValidateBindingForClient(ctx, saID, &saOrg); !errors.Is(err, ErrServiceAccountInactive) {
		t.Errorf("an inactive SA must be ErrServiceAccountInactive, got %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if err := mk(true, &past).ValidateBindingForClient(ctx, saID, &saOrg); !errors.Is(err, ErrServiceAccountExpired) {
		t.Errorf("an expired SA must be ErrServiceAccountExpired, got %v", err)
	}
}
