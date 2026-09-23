package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// lookupManagedUser is the ADMIN-MANAGEMENT read of a user by id: an admin
// reading, updating, re-enabling, approving, resetting, deleting or assigning
// roles to a user of their scope. It SEES A DISABLED (banned) USER — the plain
// repository.GetByID filters banned = false, which made a disabled user 404
// on GET /api/v1/users/:id and made PUT {"active": true} impossible, so a
// disabled user could never be enabled again (OSS-REENABLE-USER).
//
// A soft-deleted user stays NOT FOUND here, exactly as GetByID answers it
// (deleted_at IS NULL): only RestoreUserForActor reads deleted rows.
//
// Authentication and session paths (login, token issue and refresh, session
// validation, MFA, profile, userinfo) keep repository.GetByID and keep
// refusing a banned user; nothing here is shared with them. Tenant and role
// checks stay in each caller, unchanged.
//
// The runtime repository is compile-time asserted to be an
// AdminUserRepository (PgxUserRepository and CachedUserRepository). A
// repository without the admin read falls back to GetByID, which keeps the
// previous behaviour for test fakes that implement only UserRepository.
func lookupManagedUser(ctx context.Context, repo repository.UserRepository, id uuid.UUID) (*domain.User, error) {
	admin, ok := repo.(repository.AdminUserRepository)
	if !ok {
		return repo.GetByID(ctx, id)
	}
	u, err := admin.GetByIDAdmin(ctx, id)
	if err != nil {
		return nil, err
	}
	if u == nil || u.DeletedAt != nil {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}
