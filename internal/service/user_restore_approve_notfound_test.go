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

// deletedFilterAdminRepo mimics the REAL repository split that made restore
// dead: its plain GetByID hides soft-deleted rows (deleted_at IS NULL), while
// GetByIDAdmin returns them. It implements AdminUserRepository so
// RestoreUserForActor's type assertion picks the admin lookup — the fix under
// test. Everything else is inherited from inMemoryUserRepo.
type deletedFilterAdminRepo struct {
	*inMemoryUserRepo
}

func (r *deletedFilterAdminRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u, err := r.inMemoryUserRepo.GetByID(ctx, id)
	if err != nil || u == nil {
		return u, err
	}
	if u.DeletedAt != nil {
		return nil, nil // soft-deleted rows are invisible to the plain read
	}
	return u, nil
}

func (r *deletedFilterAdminRepo) GetByIDAdmin(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.inMemoryUserRepo.GetByID(ctx, id) // deleted-inclusive
}

func (r *deletedFilterAdminRepo) GetByEmailAdmin(context.Context, string) (*domain.User, error) {
	return nil, nil
}

func (r *deletedFilterAdminRepo) ListDeleted(context.Context, repository.Pagination) ([]*domain.User, int, error) {
	return nil, 0, nil
}

func (r *deletedFilterAdminRepo) ListAll(context.Context, repository.ListUserOptions) ([]*domain.User, int, error) {
	return nil, 0, nil
}

func (r *deletedFilterAdminRepo) HardDelete(context.Context, uuid.UUID) error { return nil }

// domainNotFoundRepo makes GetByID surface domain.ErrUserNotFound for a
// truly-absent id, exactly as the real scanUser/pgx.ErrNoRows path does — the
// condition the approve/reset-mfa handlers previously mis-mapped to 500.
type domainNotFoundRepo struct {
	*inMemoryUserRepo
}

func (r *domainNotFoundRepo) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

// Restore MUST recover a soft-deleted user. Before the fix,
// RestoreUserForActor read through the deleted-filtered GetByID and could
// never see the row — restore was permanently 404 (USER-RESTORE-DEAD-1).
// Mutating the fix (assertion back to GetByID) makes this test fail.
// RULE: RESTORE-RECOVERS-DELETED-1
func TestRestoreUserForActor_RecoversSoftDeletedUser(t *testing.T) {
	repo := &deletedFilterAdminRepo{inMemoryUserRepo: newUserRepo()}
	svc := NewUserService(nil, repo)
	orgID := uuid.New()
	deletedAt := time.Now().UTC()
	u := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, DeletedAt: &deletedAt}
	repo.rows[u.ID] = u

	// D-025: a site_admin never restores a tenant's user; the organization's
	// own org_admin does.
	if err := svc.RestoreUserForActor(context.Background(), siteAdmin(), u.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("site_admin restore of a tenant user = %v, want ErrForbidden", err)
	}
	if u.DeletedAt == nil {
		t.Fatalf("a refused restore still cleared deleted_at")
	}
	if err := svc.RestoreUserForActor(context.Background(), orgAdminActor(orgID), u.ID); err != nil {
		t.Fatalf("restore of a soft-deleted user must succeed via the admin lookup, got %v", err)
	}
	if u.DeletedAt != nil {
		t.Fatalf("restore must clear deleted_at, still set")
	}
}

// RULE USER-RESTORE-DEAD-1 (authorization preserved): an org_admin of another
// tenant must NOT restore a deleted user, and the refusal is the
// anti-enumeration errUserNotFound, not success or a distinguishable 403.
func TestRestoreUserForActor_CrossTenantStillRefused(t *testing.T) {
	repo := &deletedFilterAdminRepo{inMemoryUserRepo: newUserRepo()}
	svc := NewUserService(nil, repo)
	orgA, orgB := uuid.New(), uuid.New()
	deletedAt := time.Now().UTC()
	u := &domain.User{ID: uuid.New(), OrganizationID: orgA, Role: domain.RoleOrgUser, DeletedAt: &deletedAt}
	repo.rows[u.ID] = u

	orgAdminB := &domain.Principal{UserID: uuid.New(), Role: domain.RoleOrgAdmin, OrganizationID: orgB}
	err := svc.RestoreUserForActor(context.Background(), orgAdminB, u.ID)
	if !errors.Is(err, ErrUserNotFound()) {
		t.Fatalf("cross-tenant restore must refuse with the not-found sentinel, got %v", err)
	}
	if u.DeletedAt == nil {
		t.Fatalf("cross-tenant restore must NOT undelete the row")
	}
}

// A nonexistent user id must map to the SERVICE not-found sentinel (which the
// handlers render as 404), not surface the raw domain error that fell to the
// handlers' default 500 (USER-APPROVE-RESETMFA-GHOST-500-1). Mutating the fix
// (dropping the domain→service translation) makes this test fail.
// RULE: USER-NOTFOUND-MAPPING-1
func TestApproveAndResetMFA_GhostMapsToServiceNotFound(t *testing.T) {
	repo := &domainNotFoundRepo{inMemoryUserRepo: newUserRepo()}
	svc := NewUserService(nil, repo)

	_, aerr := svc.ApproveRegistrationForActor(context.Background(), siteAdmin(), uuid.New())
	if !errors.Is(aerr, ErrUserNotFound()) {
		t.Fatalf("approve of a nonexistent user must map to the service not-found sentinel, got %v", aerr)
	}

	_, rerr := svc.ResetMFAForActor(context.Background(), siteAdmin(), uuid.New())
	if !errors.Is(rerr, ErrUserNotFound()) {
		t.Fatalf("reset-mfa of a nonexistent user must map to the service not-found sentinel, got %v", rerr)
	}
}

// domainNotFoundAdminRepo makes the deleted-inclusive admin lookup surface
// domain.ErrUserNotFound for an absent id, as PgxUserRepository.GetByIDAdmin
// does through scanUser.
type domainNotFoundAdminRepo struct {
	*deletedFilterAdminRepo
}

func (r *domainNotFoundAdminRepo) GetByIDAdmin(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, domain.ErrUserNotFound
}

// Restore of a nonexistent id is the service not-found sentinel (404), for
// either admin: once the route admitted an org_admin and mapped its errors as
// reset-mfa does, the raw repository error fell to the handler's 500
// (e2e-full, v0.9.5).
func TestRestoreUserForActor_GhostMapsToServiceNotFound(t *testing.T) {
	repo := &domainNotFoundAdminRepo{&deletedFilterAdminRepo{inMemoryUserRepo: newUserRepo()}}
	svc := NewUserService(nil, repo)
	for name, actor := range map[string]*domain.Principal{"site_admin": siteAdmin(), "org_admin": orgAdminActor(uuid.New())} {
		if err := svc.RestoreUserForActor(context.Background(), actor, uuid.New()); !errors.Is(err, ErrUserNotFound()) {
			t.Errorf("%s restore of a nonexistent user = %v, want the service not-found sentinel", name, err)
		}
	}
}

// Restore MUST NOT silently fall back to the deleted-filtered GetByID when the
// repository lacks admin support — that would reintroduce USER-RESTORE-DEAD-1
// invisibly. Built on a pure UserRepository (inMemoryUserRepo, whose unfiltered
// GetByID would happily "succeed" on a deleted row), restore fails LOUDLY with
// the admin-required sentinel. Mutating the fix back to the silent GetByID
// fallback makes this test fail (restore returns nil instead of the sentinel).
// RULE: RESTORE-NO-SILENT-FALLBACK-1
func TestRestoreUserForActor_NonAdminRepoFailsLoudly(t *testing.T) {
	repo := newUserRepo() // pure UserRepository, NOT an AdminUserRepository
	svc := NewUserService(nil, repo)
	deletedAt := time.Now().UTC()
	u := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, DeletedAt: &deletedAt}
	repo.rows[u.ID] = u

	err := svc.RestoreUserForActor(context.Background(), siteAdmin(), u.ID)
	if !errors.Is(err, ErrRestoreRequiresAdminRepo()) {
		t.Fatalf("restore on a non-admin repo must fail loudly (admin-required), not silently degrade, got %v", err)
	}
}
