package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PgxOrganizationDomainRepository is the pgx-backed implementation of
// repository.OrganizationDomainRepository introduced in slice 1 of the
// org-admin Domains feature. The repository is the only writer to the
// organization_domains table; no HTTP surface exists yet.
type PgxOrganizationDomainRepository struct {
	db DBTX
}

// NewPgxOrganizationDomainRepository constructs the repository.
func NewPgxOrganizationDomainRepository(db DBTX) *PgxOrganizationDomainRepository {
	return &PgxOrganizationDomainRepository{db: db}
}

// Compile-time interface check.
var _ repository.OrganizationDomainRepository = (*PgxOrganizationDomainRepository)(nil)

// orgDomainColumns is the canonical SELECT column list. Kept as a single
// constant so every SELECT in this file (and any future cross-file
// reader) projects the same shape.
const orgDomainColumns = `id, organization_id, domain, is_primary, verified_at, verification_token_hash, verification_token_expires_at, verification_attempts, created_at, updated_at`

// scanOrganizationDomain reads a single row from the canonical column
// projection. citext is decoded as text on the wire so a plain *string
// scan target is correct.
func scanOrganizationDomain(row pgx.Row) (*domain.OrganizationDomain, error) {
	var d domain.OrganizationDomain
	err := row.Scan(
		&d.ID,
		&d.OrganizationID,
		&d.Domain,
		&d.IsPrimary,
		&d.VerifiedAt,
		&d.VerificationTokenHash,
		&d.VerificationTokenExpiresAt,
		&d.VerificationAttempts,
		&d.CreatedAt,
		&d.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// CreateOrganizationDomain inserts a new row and maps the table's
// uniqueness violations to the package's sentinel errors so service
// callers do not need to inspect pgconn error codes.
func (r *PgxOrganizationDomainRepository) CreateOrganizationDomain(ctx context.Context, d *domain.OrganizationDomain) (*domain.OrganizationDomain, error) {
	if d == nil {
		return nil, errors.New("organization domain is required")
	}
	if err := d.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrOrganizationDomainInvalid, err.Error())
	}

	normalized := domain.NormalizeDomain(d.Domain)

	row := r.db.QueryRow(ctx, `
		INSERT INTO organization_domains (
			organization_id,
			domain,
			is_primary,
			verified_at,
			verification_token_hash,
			verification_token_expires_at,
			verification_attempts
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+orgDomainColumns,
		d.OrganizationID,
		normalized,
		d.IsPrimary,
		d.VerifiedAt,
		d.VerificationTokenHash,
		d.VerificationTokenExpiresAt,
		d.VerificationAttempts,
	)

	created, err := scanOrganizationDomain(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch {
			case strings.Contains(pgErr.ConstraintName, "uq_org_domains_verified_domain"):
				return nil, domain.ErrOrganizationDomainVerifiedByOther
			case strings.Contains(pgErr.ConstraintName, "uq_org_domains_org_domain"),
				strings.Contains(pgErr.ConstraintName, "uq_org_domains_one_primary_per_org"):
				return nil, domain.ErrOrganizationDomainAlreadyExists
			default:
				return nil, domain.ErrOrganizationDomainAlreadyExists
			}
		}
		return nil, fmt.Errorf("failed to create organization domain: %w", err)
	}
	return created, nil
}

// GetOrganizationDomainByID returns a row by id or
// domain.ErrOrganizationDomainNotFound.
func (r *PgxOrganizationDomainRepository) GetOrganizationDomainByID(ctx context.Context, id uuid.UUID) (*domain.OrganizationDomain, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+orgDomainColumns+`
		FROM organization_domains
		WHERE id = $1`, id)

	d, err := scanOrganizationDomain(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationDomainNotFound
		}
		return nil, fmt.Errorf("failed to get organization domain by id: %w", err)
	}
	return d, nil
}

// ListOrganizationDomainsByOrganization returns the org's rows, primary
// first then newest-first. Returns an empty slice when no rows exist.
func (r *PgxOrganizationDomainRepository) ListOrganizationDomainsByOrganization(ctx context.Context, organizationID uuid.UUID) ([]*domain.OrganizationDomain, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+orgDomainColumns+`
		FROM organization_domains
		WHERE organization_id = $1
		ORDER BY is_primary DESC, created_at DESC, id ASC`,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list organization domains: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.OrganizationDomain, 0)
	for rows.Next() {
		d, err := scanOrganizationDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan organization domain row: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate organization domain rows: %w", err)
	}
	return out, nil
}

// GetVerifiedOrganizationDomainByDomain returns the single verified row
// for the given domain string globally. Slice 3 is expected to call this
// from the public-lookup path; nothing calls it yet.
func (r *PgxOrganizationDomainRepository) GetVerifiedOrganizationDomainByDomain(ctx context.Context, domainName string) (*domain.OrganizationDomain, error) {
	normalized := domain.NormalizeDomain(domainName)
	row := r.db.QueryRow(ctx, `
		SELECT `+orgDomainColumns+`
		FROM organization_domains
		WHERE domain = $1
		  AND verified_at IS NOT NULL`,
		normalized,
	)
	d, err := scanOrganizationDomain(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOrganizationDomainNotFound
		}
		return nil, fmt.Errorf("failed to get verified organization domain: %w", err)
	}
	return d, nil
}

// SetOrganizationDomainVerified flips a pending row to verified at the
// supplied timestamp and clears any outstanding verification token state
// (hash + expires_at). The verification_attempts counter is intentionally
// preserved so it remains observable for post-hoc audit. The 23505
// surface from the verified-domain partial unique index is mapped to
// domain.ErrOrganizationDomainVerifiedByOther so a future verification
// handler does not have to inspect pg error codes.
func (r *PgxOrganizationDomainRepository) SetOrganizationDomainVerified(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error {
	cmd, err := r.db.Exec(ctx, `
		UPDATE organization_domains
		SET verified_at = $1,
		    verification_token_hash = NULL,
		    verification_token_expires_at = NULL,
		    updated_at = NOW()
		WHERE id = $2`,
		verifiedAt,
		id,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
			strings.Contains(pgErr.ConstraintName, "uq_org_domains_verified_domain") {
			return domain.ErrOrganizationDomainVerifiedByOther
		}
		return fmt.Errorf("failed to mark organization domain verified: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrOrganizationDomainNotFound
	}
	return nil
}

// IncrementOrganizationDomainVerificationAttempts bumps the row's
// verification_attempts counter by 1. Both id AND organization_id are
// bound into the WHERE so a caller cannot increment counters across
// tenants. Returns domain.ErrOrganizationDomainNotFound when no row
// matched.
func (r *PgxOrganizationDomainRepository) IncrementOrganizationDomainVerificationAttempts(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error {
	cmd, err := r.db.Exec(ctx, `
		UPDATE organization_domains
		SET verification_attempts = verification_attempts + 1,
		    updated_at = NOW()
		WHERE id = $1
		  AND organization_id = $2`,
		id,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf("failed to increment organization domain verification attempts: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrOrganizationDomainNotFound
	}
	return nil
}

// DeleteOrganizationDomain removes a row. Both id AND organization_id
// are bound into the WHERE clause so a caller cannot delete rows outside
// its own org even if the higher layer were ever to trust a request-
// supplied org id by mistake. The two no-match cases (wrong id, right
// id but wrong org) are intentionally collapsed into a single not-found
// error so the call cannot be used as an existence oracle.
func (r *PgxOrganizationDomainRepository) DeleteOrganizationDomain(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error {
	cmd, err := r.db.Exec(ctx, `
		DELETE FROM organization_domains
		WHERE id = $1
		  AND organization_id = $2`,
		id,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete organization domain: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrOrganizationDomainNotFound
	}
	return nil
}

// SetPrimaryOrganizationDomain atomically demotes the org's current
// primary (if any) and promotes the supplied row, in a single
// transaction. Both id and organization_id are required and bound into
// every statement in the transaction so the cross-tenancy constraint
// holds end-to-end. The partial unique index
// uq_org_domains_one_primary_per_org is the database-side belt-and-
// suspenders if the transaction were ever to race.
func (r *PgxOrganizationDomainRepository) SetPrimaryOrganizationDomain(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any non-commit path

	// Demote any existing primary for this org. RowsAffected may be 0
	// (no current primary) and that is a valid state — do not fail.
	if _, err := tx.Exec(ctx, `
		UPDATE organization_domains
		SET is_primary = false,
		    updated_at = NOW()
		WHERE organization_id = $1
		  AND is_primary = true
		  AND id <> $2`,
		organizationID,
		id,
	); err != nil {
		return fmt.Errorf("failed to demote previous primary organization domain: %w", err)
	}

	// Promote the supplied row, scoped by organization_id so a caller
	// cannot promote a row that belongs to another org.
	cmd, err := tx.Exec(ctx, `
		UPDATE organization_domains
		SET is_primary = true,
		    updated_at = NOW()
		WHERE id = $1
		  AND organization_id = $2`,
		id,
		organizationID,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
			strings.Contains(pgErr.ConstraintName, "uq_org_domains_one_primary_per_org") {
			return domain.ErrOrganizationDomainAlreadyExists
		}
		return fmt.Errorf("failed to promote organization domain to primary: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return domain.ErrOrganizationDomainNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit set-primary transaction: %w", err)
	}
	return nil
}
