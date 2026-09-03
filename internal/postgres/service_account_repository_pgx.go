package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
)

// PgxServiceAccountRepository implements repository.ServiceAccountRepository with pgx
type PgxServiceAccountRepository struct {
	db DBTX
}

// NewPgxServiceAccountRepository creates a new instance
func NewPgxServiceAccountRepository(db DBTX) *PgxServiceAccountRepository {
	return &PgxServiceAccountRepository{db: db}
}

var _ repository.ServiceAccountRepository = (*PgxServiceAccountRepository)(nil)

func (r *PgxServiceAccountRepository) Create(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("service_account_repo", "create", "all"))
	defer timer.ObserveDuration()

	query := `
		INSERT INTO service_accounts (organization_id, name, description, active, expires_at, role, owner_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING id, created_at, updated_at`

	var id uuid.UUID
	roleStr := string(sa.Role)
	if roleStr == "" {
		roleStr = string(domain.RoleOrgAdmin)
	}
	err := r.db.QueryRow(ctx, query, sa.OrganizationID, sa.Name, sa.Description, sa.Active, sa.ExpiresAt, roleStr, sa.OwnerUserID).Scan(
		&id,
		&sa.CreatedAt,
		&sa.UpdatedAt,
	)

	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("service_account_repo", "create", "error").Observe(timer.ObserveDuration().Seconds())
		if isSANameTaken(err) {
			return nil, domain.ErrServiceAccountNameTaken
		}
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("service_account_repo", "create", "success").Observe(timer.ObserveDuration().Seconds())
	sa.ID = id
	return sa, nil
}

// isSANameTaken reports whether err is the per-organization live-name unique
// violation (uq_service_accounts_org_name_live, migration 0030 — gap E).
func isSANameTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" &&
		strings.Contains(pgErr.ConstraintName, "uq_service_accounts_org_name_live")
}

func (r *PgxServiceAccountRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.ServiceAccount, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_id", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT id, organization_id, name, description, active, expires_at, role, owner_user_id, created_at, updated_at
		FROM service_accounts
		WHERE id = $1 AND deleted_at IS NULL`

	var sa domain.ServiceAccount
	var roleStr string
	err := r.db.QueryRow(ctx, query, id).Scan(
		&sa.ID,
		&sa.OrganizationID,
		&sa.Name,
		&sa.Description,
		&sa.Active,
		&sa.ExpiresAt,
		&roleStr,
		&sa.OwnerUserID,
		&sa.CreatedAt,
		&sa.UpdatedAt,
	)
	sa.Role = domain.UserRole(roleStr)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrServiceAccountNotFound
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_id", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_id", "success").Observe(timer.ObserveDuration().Seconds())
	return &sa, nil
}

func (r *PgxServiceAccountRepository) GetByName(ctx context.Context, orgID uuid.UUID, name string) (*domain.ServiceAccount, error) {
	timer := prometheus.NewTimer(metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_name", "all"))
	defer timer.ObserveDuration()

	query := `
		SELECT id, organization_id, name, description, active, expires_at, role, owner_user_id, created_at, updated_at
		FROM service_accounts
		WHERE organization_id = $1 AND name = $2 AND deleted_at IS NULL`

	var sa domain.ServiceAccount
	var roleStr string
	err := r.db.QueryRow(ctx, query, orgID, name).Scan(
		&sa.ID,
		&sa.OrganizationID,
		&sa.Name,
		&sa.Description,
		&sa.Active,
		&sa.ExpiresAt,
		&roleStr,
		&sa.OwnerUserID,
		&sa.CreatedAt,
		&sa.UpdatedAt,
	)
	sa.Role = domain.UserRole(roleStr)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrServiceAccountNotFound
	}
	if err != nil {
		metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_name", "error").Observe(timer.ObserveDuration().Seconds())
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}

	metrics.DBQueryDuration.WithLabelValues("service_account_repo", "get_by_name", "success").Observe(timer.ObserveDuration().Seconds())
	return &sa, nil
}

func (r *PgxServiceAccountRepository) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.ServiceAccount, error) {
	query := `
		SELECT id, organization_id, name, description, active, expires_at, role, owner_user_id, created_at, updated_at
		FROM service_accounts
		WHERE organization_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT 500`

	rows, err := r.db.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*domain.ServiceAccount
	for rows.Next() {
		var sa domain.ServiceAccount
		var roleStr string
		if err := rows.Scan(&sa.ID, &sa.OrganizationID, &sa.Name, &sa.Description, &sa.Active, &sa.ExpiresAt, &roleStr, &sa.OwnerUserID, &sa.CreatedAt, &sa.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan service account: %w", err)
		}
		sa.Role = domain.UserRole(roleStr)
		accounts = append(accounts, &sa)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating service account rows: %w", err)
	}
	return accounts, nil
}

// Update writes the mutable columns of a service account.
//
// THE-SILENT-EXPIRY: expires_at is one of them. The statement used to cover
// {name, description, role} only, while ServiceAccountService.UpdateForActor
// assigned ExpiresAt on the aggregate — so a PUT carrying only expires_at
// answered 200 and stored nothing, and the account went on minting tokens
// past the expiry its operator had just set. The column is written from the
// aggregate, so "not supplied" (the service leaves the loaded value in
// place) rewrites the same value and nothing changes.
//
// Ownership and the active flag keep their own statements (UpdateOwner,
// UpdateActive): they are audited lifecycle mutations, not field edits.
func (r *PgxServiceAccountRepository) Update(ctx context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	query := `
		UPDATE service_accounts
		SET name = $1, description = $2, role = $3, expires_at = $4, updated_at = NOW()
		WHERE id = $5 AND organization_id = $6
		RETURNING updated_at`

	err := r.db.QueryRow(ctx, query, sa.Name, sa.Description, string(sa.Role), sa.ExpiresAt, sa.ID, sa.OrganizationID).Scan(&sa.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrServiceAccountNotFound
	}
	if err != nil {
		if isSANameTaken(err) {
			return nil, domain.ErrServiceAccountNameTaken
		}
		return nil, fmt.Errorf("failed to update service account: %w", err)
	}
	return sa, nil
}

func (r *PgxServiceAccountRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE service_accounts SET last_used_at = NOW() WHERE id = $1 AND deleted_at IS NULL`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to update service account last_used_at: %w", err)
	}
	return nil
}

func (r *PgxServiceAccountRepository) Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error {
	query := `
		UPDATE service_accounts
		SET deleted_at = NOW()
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`
	result, err := r.db.Exec(ctx, query, id, orgID)
	if err != nil {
		return fmt.Errorf("failed to soft-delete service account: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}
	return nil
}

// UpdateActive flips the service_accounts.active column for a non-
// deleted row in the given organization (slice
// identuum-20260530-service-account-disable-enable-backend). The
// existing Update method does NOT touch `active` — it intentionally
// scoped to {name, description, role}. Disable/enable is a separate
// lifecycle mutation; surfacing it as its own repo method keeps both
// concerns auditable + unambiguous.
//
// WHERE clause mirrors the Delete soft-delete guard: row must belong
// to the supplied organization AND not be soft-deleted. The
// organization scope is the load-bearing tenant gate at the SQL layer;
// the service-layer Disable/Enable also enforces actor.OrganizationID
// == sa.OrganizationID before calling.
//
// updated_at is bumped via NOW() so the existing audit / activity
// feeds reflect the lifecycle change. The `active` column is set
// unconditionally (no idempotency at the SQL layer) so the service
// can record the previous_active state in the audit metadata.
// UpdateOwner sets service_accounts.owner_user_id for a non-deleted row in
// the given organization (THE-OWNERLESS-ACCOUNT). Same shape as
// UpdateActive: its own statement so an ownership change cannot clobber
// name/description/role, the organization scope as the load-bearing tenant
// gate at the SQL layer, and updated_at bumped so the activity feeds show
// the change. The service layer has already resolved the actor's authority
// and the eligibility of the new owner.
func (r *PgxServiceAccountRepository) UpdateOwner(ctx context.Context, id uuid.UUID, orgID uuid.UUID, ownerUserID uuid.UUID) error {
	query := `
		UPDATE service_accounts
		SET owner_user_id = $3, updated_at = NOW()
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`
	result, err := r.db.Exec(ctx, query, id, orgID, ownerUserID)
	if err != nil {
		return fmt.Errorf("failed to update service account owner: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}
	return nil
}

func (r *PgxServiceAccountRepository) UpdateActive(ctx context.Context, id uuid.UUID, orgID uuid.UUID, active bool) error {
	query := `
		UPDATE service_accounts
		SET active = $3, updated_at = NOW()
		WHERE id = $1 AND organization_id = $2 AND deleted_at IS NULL`
	result, err := r.db.Exec(ctx, query, id, orgID, active)
	if err != nil {
		return fmt.Errorf("failed to update service account active: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("service account not found")
	}
	return nil
}
