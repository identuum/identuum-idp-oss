package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// OSS-GUARDS: an organization's last active org_admin is never disabled,
// demoted or deleted by an org_admin (contracts/AdminPermissionsModel.md
// line 3 wants identuum-idp-ce's rule here too). "Active" is what
// CountOrgAdminsByOrganization counts: role org_admin, not banned, not
// deleted. The check and the write run in ONE transaction that first locks
// the organization row, so two concurrent removals of an organization's last
// two org_admins serialize and the second sees the first.

var _ repository.OrgAdminKeepingDeleter = (*PgxUserRepository)(nil)

// lockOrgKeepingActiveAdmin locks orgID's row, then reports
// domain.ErrLastOrgAdmin when userID is an active org_admin of orgID and no
// other active org_admin remains. A user or organization that is not there
// is domain.ErrUserNotFound.
func lockOrgKeepingActiveAdmin(ctx context.Context, tx pgx.Tx, orgID, userID uuid.UUID) error {
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`, orgID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("lock organization: %w", err)
	}
	var role string
	var banned, deleted bool
	err := tx.QueryRow(ctx, `
SELECT role::text, banned, deleted_at IS NOT NULL
  FROM users
 WHERE id = $1 AND organization_id = $2
   FOR UPDATE`, userID, orgID).Scan(&role, &banned, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("lock user: %w", err)
	}
	if domain.UserRole(role) != domain.RoleOrgAdmin || banned || deleted {
		return nil // not an active org_admin: nothing to keep
	}
	var others int
	if err := tx.QueryRow(ctx, `
SELECT COUNT(*)
  FROM users
 WHERE organization_id = $1 AND id <> $2
   AND role = 'org_admin' AND deleted_at IS NULL AND banned = false`, orgID, userID).Scan(&others); err != nil {
		return fmt.Errorf("count org_admins: %w", err)
	}
	if others == 0 {
		return domain.ErrLastOrgAdmin
	}
	return nil
}

// updateKeepingActiveOrgAdmin is Update with opts.KeepActiveOrgAdmin: a ban
// or a demotion of an active org_admin runs inside the locking transaction.
// Any other update needs no lock and runs as a plain Update.
func (r *PgxUserRepository) updateKeepingActiveOrgAdmin(ctx context.Context, id, orgID uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	opts.KeepActiveOrgAdmin = false
	removes := (opts.Banned != nil && *opts.Banned) || (opts.Role != nil && *opts.Role != domain.RoleOrgAdmin)
	if !removes {
		return r.Update(ctx, id, orgID, opts)
	}
	if orgID == uuid.Nil {
		return nil, domain.ErrUserNotFound
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOrgKeepingActiveAdmin(ctx, tx, orgID, id); err != nil {
		return nil, err
	}
	updated, err := NewPgxUserRepository(tx).Update(ctx, id, orgID, opts)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to update user: commit: %w", err)
	}
	return updated, nil
}

// DeleteKeepingActiveOrgAdmin soft-deletes id of orgID like Delete, refusing
// with domain.ErrLastOrgAdmin when id is the organization's last active
// org_admin.
func (r *PgxUserRepository) DeleteKeepingActiveOrgAdmin(ctx context.Context, id, orgID uuid.UUID) error {
	if orgID == uuid.Nil {
		return domain.ErrUserNotFound
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete user: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockOrgKeepingActiveAdmin(ctx, tx, orgID, id); err != nil {
		return err
	}
	if err := NewPgxUserRepository(tx).Delete(ctx, id, orgID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to delete user: commit: %w", err)
	}
	return nil
}
