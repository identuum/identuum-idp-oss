package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/jackc/pgx/v5"
)

type PgClaimRepository struct {
	db DBTX
}

func NewPgClaimRepository(db DBTX) *PgClaimRepository {
	return &PgClaimRepository{db: db}
}

// Ensure interface compliance
var (
	_ repository.ClaimRepository        = (*PgClaimRepository)(nil)
	_ repository.ClaimConsumeTransactor = (*PgClaimRepository)(nil)
)

// ConsumeInTx runs one claim consume in ONE transaction (OSS-SEC). fn's
// claim and user repositories are bound to it,
// so the claim row it locks, the attempt count, the burn and the org_admin it
// creates commit together when fn returns nil and are all rolled back when fn
// returns an error. Before this, a user creation that failed after the burn
// left the link burned and no user created.
func (r *PgClaimRepository) ConsumeInTx(ctx context.Context, fn func(repository.ClaimConsumeTx) error) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(&pgClaimConsumeTx{claims: &PgClaimRepository{db: tx}, users: NewPgxUserRepository(tx)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pgClaimConsumeTx is repository.ClaimConsumeTx over one transaction.
type pgClaimConsumeTx struct {
	claims *PgClaimRepository
	users  *PgxUserRepository
}

func (t *pgClaimConsumeTx) LockByTokenHash(ctx context.Context, hash string) (*domain.OrganizationClaim, error) {
	return t.claims.getByTokenHash(ctx, hash, true)
}

func (t *pgClaimConsumeTx) IncrementAttemptCount(ctx context.Context, id uuid.UUID) (int, error) {
	return t.claims.IncrementAttemptCount(ctx, id)
}

func (t *pgClaimConsumeTx) Delete(ctx context.Context, id uuid.UUID) error {
	return t.claims.Delete(ctx, id)
}

func (t *pgClaimConsumeTx) FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error) {
	return t.users.FindUsersByEmail(ctx, email)
}

func (t *pgClaimConsumeTx) CreateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	return t.users.Create(ctx, user)
}

func (r *PgClaimRepository) Create(ctx context.Context, claim *domain.OrganizationClaim) error {
	query := `
		INSERT INTO organization_claims (id, organization_id, token_hash, expires_at, created_at, target_email, email_bound)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Exec(ctx, query,
		claim.ID,
		claim.OrganizationID,
		claim.TokenHash,
		claim.ExpiresAt,
		claim.CreatedAt,
		claim.TargetEmail,
		claim.EmailBound,
	)
	return err
}

func (r *PgClaimRepository) GetByTokenHash(ctx context.Context, hash string) (*domain.OrganizationClaim, error) {
	return r.getByTokenHash(ctx, hash, false)
}

// getByTokenHash reads a claim by its token hash; lock holds the row
// (FOR UPDATE) until the caller's transaction ends.
func (r *PgClaimRepository) getByTokenHash(ctx context.Context, hash string, lock bool) (*domain.OrganizationClaim, error) {
	query := `
		SELECT id, organization_id, token_hash, expires_at, created_at, attempt_count,
		       COALESCE(target_email, '') AS target_email,
		       email_bound
		FROM organization_claims
		WHERE token_hash = $1
	`
	if lock {
		query += ` FOR UPDATE`
	}
	var claim domain.OrganizationClaim
	err := r.db.QueryRow(ctx, query, hash).Scan(
		&claim.ID,
		&claim.OrganizationID,
		&claim.TokenHash,
		&claim.ExpiresAt,
		&claim.CreatedAt,
		&claim.AttemptCount,
		&claim.TargetEmail,
		&claim.EmailBound,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrClaimNotFound
		}
		return nil, err
	}
	return &claim, nil
}

// Delete burns the claim row and reports whether THIS caller is the one that
// burned it.
//
// P3-2: the command tag used to be discarded, so a second concurrent
// ConsumeClaim deleted zero rows, saw err == nil, and carried on to mint a
// SECOND org_admin. The "burn-before-write" comment in ClaimService.ConsumeClaim
// described a guarantee the SQL did not provide: the delete was idempotent, and
// idempotent is exactly what you do NOT want when the delete IS the mutex.
//
// Returning domain.ErrClaimNotFound on zero rows makes the database the
// arbiter — one winner, and the loser takes the existing not-found path.
func (r *PgClaimRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM organization_claims WHERE id = $1`
	tag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrClaimNotFound
	}
	return nil
}

func (r *PgClaimRepository) DeleteExpired(ctx context.Context) (int64, error) {
	// Delete ONLY rows past their expiry, on the DB clock (NOW()), so a
	// live delegation token inside its validity window is never removed
	// (the service IsValid check remains authoritative). Mirrors the
	// oidc_states sweeper shape.
	query := `DELETE FROM organization_claims WHERE expires_at < NOW()`
	tag, err := r.db.Exec(ctx, query)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// IncrementAttemptCount atomically increments attempt_count for the claim and
// returns the new value. Returns domain.ErrClaimNotFound if the row no longer
// exists (e.g. deleted by a concurrent request at the 3rd attempt boundary).
func (r *PgClaimRepository) IncrementAttemptCount(ctx context.Context, id uuid.UUID) (int, error) {
	query := `
		UPDATE organization_claims
		SET attempt_count = attempt_count + 1
		WHERE id = $1
		RETURNING attempt_count
	`
	var newCount int
	err := r.db.QueryRow(ctx, query, id).Scan(&newCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, domain.ErrClaimNotFound
		}
		return 0, err
	}
	return newCount, nil
}
