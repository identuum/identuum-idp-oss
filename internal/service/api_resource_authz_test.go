package service

// THE-INVERTED-GUARD (2026-08-30): APIResourceService authorization teeth.
// AdminPermissionsModel.md is law — API resources carry OrganizationID, so
// they are managed by the tenant's own org_admin ONLY: site_admin is
// forbidden (it was the sole role admitted before this slice), org_user is
// forbidden, nil is forbidden, and a foreign org's id reads as NOT-FOUND,
// never a confirming 403 (the requireOrgAdmin rationale from the
// service-account paths).

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func apiResourcePrincipal(role domain.UserRole, orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Email:          "actor@example.test",
		Role:           role,
	}
}

// seedAPIResource creates one resource in ownOrg through the service's own
// front door so the fixture always matches the enforced contract.
func seedAuthzAPIResource(t *testing.T, svc *APIResourceService, ownOrg uuid.UUID) *domain.APIResource {
	t.Helper()
	admin := apiResourcePrincipal(domain.RoleOrgAdmin, ownOrg)
	resource, _, err := svc.Create(context.Background(), admin, CreateAPIResourceOptions{
		OrganizationID: ownOrg,
		Name:           "Seeded",
		Audience:       "https://seeded.example.test",
		Active:         true,
		TokenTTLSecs:   3600,
	})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	return resource
}

func TestAPIResourceAuthz_ForbiddenActors(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	ownOrg := uuid.New()
	seeded := seedAuthzAPIResource(t, svc, ownOrg)
	pagination := repository.Pagination{Page: 1, PageSize: 10}

	for name, actor := range map[string]*domain.Principal{
		"nil actor":  nil,
		"site_admin": apiResourcePrincipal(domain.RoleSiteAdmin, ownOrg),
		"org_user":   apiResourcePrincipal(domain.RoleOrgUser, ownOrg),
	} {
		if _, _, err := svc.List(context.Background(), actor, pagination); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s List err = %v, want ErrAPIResourceForbidden", name, err)
		}
		if _, err := svc.GetByID(context.Background(), actor, seeded.ID); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s GetByID err = %v, want ErrAPIResourceForbidden", name, err)
		}
		if _, _, err := svc.Create(context.Background(), actor, CreateAPIResourceOptions{
			Name: "X", Audience: "https://x.example.test", Active: true, TokenTTLSecs: 60,
		}); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s Create err = %v, want ErrAPIResourceForbidden", name, err)
		}
		if _, err := svc.Update(context.Background(), actor, seeded.ID, UpdateAPIResourceOptions{}); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s Update err = %v, want ErrAPIResourceForbidden", name, err)
		}
		if err := svc.Delete(context.Background(), actor, seeded.ID); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s Delete err = %v, want ErrAPIResourceForbidden", name, err)
		}
		if _, _, err := svc.RegenerateSecret(context.Background(), actor, seeded.ID); !errors.Is(err, ErrAPIResourceForbidden) {
			t.Errorf("%s RegenerateSecret err = %v, want ErrAPIResourceForbidden", name, err)
		}
	}
}

func TestAPIResourceAuthz_ForeignOrgReadsAsMiss(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	ownOrg := uuid.New()
	seeded := seedAuthzAPIResource(t, svc, ownOrg)
	foreign := apiResourcePrincipal(domain.RoleOrgAdmin, uuid.New())

	if _, err := svc.GetByID(context.Background(), foreign, seeded.ID); !errors.Is(err, ErrAPIResourceNotFound()) {
		t.Errorf("foreign GetByID err = %v, want not-found (never a confirming 403)", err)
	}
	if _, err := svc.Update(context.Background(), foreign, seeded.ID, UpdateAPIResourceOptions{}); !errors.Is(err, ErrAPIResourceNotFound()) {
		t.Errorf("foreign Update err = %v, want not-found", err)
	}
	if _, _, err := svc.RegenerateSecret(context.Background(), foreign, seeded.ID); !errors.Is(err, ErrAPIResourceNotFound()) {
		t.Errorf("foreign RegenerateSecret err = %v, want not-found", err)
	}
	// Create naming ANOTHER organization reads as a miss too.
	if _, _, err := svc.Create(context.Background(), foreign, CreateAPIResourceOptions{
		OrganizationID: ownOrg, Name: "X", Audience: "https://x2.example.test", Active: true, TokenTTLSecs: 60,
	}); !errors.Is(err, ErrAPIResourceNotFound()) {
		t.Errorf("foreign-org Create err = %v, want not-found", err)
	}
	// Idempotent delete: the org-scoped DELETE cannot match a foreign row —
	// no error, and the row survives untouched.
	if err := svc.Delete(context.Background(), foreign, seeded.ID); err != nil {
		t.Errorf("foreign Delete err = %v, want nil (idempotent miss)", err)
	}
	own := apiResourcePrincipal(domain.RoleOrgAdmin, ownOrg)
	if still, err := svc.GetByID(context.Background(), own, seeded.ID); err != nil || still == nil {
		t.Errorf("seeded row must survive the foreign delete: %v", err)
	}
	// The foreign admin's own-org view never leaks the other tenant's rows.
	rows, total, err := svc.List(context.Background(), foreign, repository.Pagination{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("foreign List: %v", err)
	}
	for _, r := range rows {
		if r.ID == seeded.ID {
			t.Errorf("foreign List leaked another org's resource")
		}
	}
	_ = total
}

func TestAPIResourceAuthz_OwnOrgAdminFullyServed(t *testing.T) {
	svc := NewAPIResourceService(nil, newAPIResourceRepo())
	ownOrg := uuid.New()
	admin := apiResourcePrincipal(domain.RoleOrgAdmin, ownOrg)
	seeded := seedAuthzAPIResource(t, svc, ownOrg)

	if got, err := svc.GetByID(context.Background(), admin, seeded.ID); err != nil || got == nil {
		t.Fatalf("own GetByID: %v", err)
	}
	if _, err := svc.Update(context.Background(), admin, seeded.ID, UpdateAPIResourceOptions{}); err != nil {
		t.Errorf("own Update: %v", err)
	}
	if _, _, err := svc.RegenerateSecret(context.Background(), admin, seeded.ID); err != nil {
		t.Errorf("own RegenerateSecret: %v", err)
	}
	// A create with a ZERO org pins to the actor's own organization.
	created, _, err := svc.Create(context.Background(), admin, CreateAPIResourceOptions{
		Name: "Pinned", Audience: "https://pinned.example.test", Active: true, TokenTTLSecs: 60,
	})
	if err != nil {
		t.Fatalf("own Create (zero org): %v", err)
	}
	if created.OrganizationID != ownOrg {
		t.Errorf("zero-org create pinned to %s, want the actor's org %s", created.OrganizationID, ownOrg)
	}
	if err := svc.Delete(context.Background(), admin, seeded.ID); err != nil {
		t.Errorf("own Delete: %v", err)
	}
}
