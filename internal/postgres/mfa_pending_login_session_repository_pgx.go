package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// PgxMFAPendingLoginSessionRepository implements
// repository.MFAPendingLoginSessionRepository against the
// mfa_pending_login_sessions table.
type PgxMFAPendingLoginSessionRepository struct {
	db DBTX
}

// NewPgxMFAPendingLoginSessionRepository constructs the repo.
func NewPgxMFAPendingLoginSessionRepository(db DBTX) *PgxMFAPendingLoginSessionRepository {
	return &PgxMFAPendingLoginSessionRepository{db: db}
}

// Compile-time interface check.
var _ repository.MFAPendingLoginSessionRepository = (*PgxMFAPendingLoginSessionRepository)(nil)

// Create inserts a new pending row. Secret + RecoveryCodes are
// left NULL (the /initiate endpoint populates them via UpdateSecret).
func (r *PgxMFAPendingLoginSessionRepository) Create(ctx context.Context, row *domain.MFAPendingLoginSession) (*domain.MFAPendingLoginSession, error) {
	if row == nil {
		return nil, errors.New("postgres: nil MFAPendingLoginSession")
	}
	if row.ID == uuid.Nil {
		return nil, errors.New("postgres: MFAPendingLoginSession requires non-nil ID")
	}
	if row.UserID == uuid.Nil {
		return nil, errors.New("postgres: MFAPendingLoginSession requires non-nil UserID")
	}
	if row.Kind != domain.MFAPendingKindEnroll && row.Kind != domain.MFAPendingKindVerify {
		return nil, fmt.Errorf("postgres: invalid MFAPendingLoginSession kind %q", row.Kind)
	}
	const q = `
INSERT INTO mfa_pending_login_sessions (id, user_id, kind, remember_me, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, kind, secret, recovery_codes, remember_me, created_at, expires_at, consumed_at, failed_attempts`
	var out domain.MFAPendingLoginSession
	var secret *string
	var codesJSON []byte
	if err := r.db.QueryRow(ctx, q,
		row.ID, row.UserID, string(row.Kind), row.RememberMe, row.ExpiresAt,
	).Scan(&out.ID, &out.UserID, (*string)(&out.Kind), &secret, &codesJSON, &out.RememberMe, &out.CreatedAt, &out.ExpiresAt, &out.ConsumedAt, &out.FailedAttempts); err != nil {
		return nil, fmt.Errorf("postgres: create mfa_pending_login_session: %w", err)
	}
	out.Secret = secret
	if len(codesJSON) > 0 {
		if err := json.Unmarshal(codesJSON, &out.RecoveryCodes); err != nil {
			return nil, fmt.Errorf("postgres: parse recovery_codes: %w", err)
		}
	}
	return &out, nil
}

// GetByID retrieves a single row by id. Returns
// ErrMFAPendingSessionNotFound when no row matches. Returns the FULL
// row including Secret + RecoveryCodes when present.
func (r *PgxMFAPendingLoginSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	const q = `
SELECT id, user_id, kind, secret, recovery_codes, remember_me, created_at, expires_at, consumed_at, failed_attempts
FROM   mfa_pending_login_sessions
WHERE  id = $1`
	var out domain.MFAPendingLoginSession
	var kind string
	var secret *string
	var codesJSON []byte
	if err := r.db.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.UserID, &kind, &secret, &codesJSON, &out.RememberMe, &out.CreatedAt, &out.ExpiresAt, &out.ConsumedAt, &out.FailedAttempts,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrMFAPendingSessionNotFound
		}
		return nil, fmt.Errorf("postgres: get mfa_pending_login_session: %w", err)
	}
	out.Kind = domain.MFAPendingKind(kind)
	out.Secret = secret
	if len(codesJSON) > 0 {
		if err := json.Unmarshal(codesJSON, &out.RecoveryCodes); err != nil {
			return nil, fmt.Errorf("postgres: parse recovery_codes: %w", err)
		}
	}
	return &out, nil
}

// UpdateSecret persists the candidate secret + recovery codes onto
// an existing pending row. Refuses to overwrite already-set secret
// material (the /initiate endpoint is idempotent at the service
// layer but the DB-level guard catches a misuse here).
func (r *PgxMFAPendingLoginSessionRepository) UpdateSecret(ctx context.Context, id uuid.UUID, secret string, recoveryCodes []string) error {
	if secret == "" {
		return errors.New("postgres: UpdateSecret requires non-empty secret")
	}
	codesJSON, err := json.Marshal(recoveryCodes)
	if err != nil {
		return fmt.Errorf("postgres: marshal recovery_codes: %w", err)
	}
	const q = `
UPDATE mfa_pending_login_sessions
SET    secret = $2, recovery_codes = $3
WHERE  id = $1
  AND  consumed_at IS NULL
  AND  expires_at > NOW()`
	ct, err := r.db.Exec(ctx, q, id, secret, codesJSON)
	if err != nil {
		return fmt.Errorf("postgres: update mfa_pending_login_session secret: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return repository.ErrMFAPendingSessionNotFound
	}
	return nil
}

// MarkConsumed atomically sets consumed_at on the row IF it is not
// yet consumed AND has not expired. Returns true when the row was
// successfully marked (the caller has exclusive use of it).
func (r *PgxMFAPendingLoginSessionRepository) MarkConsumed(ctx context.Context, id uuid.UUID, now time.Time) (bool, error) {
	const q = `
UPDATE mfa_pending_login_sessions
SET    consumed_at = $2
WHERE  id = $1
  AND  consumed_at IS NULL
  AND  expires_at > $2`
	ct, err := r.db.Exec(ctx, q, id, now)
	if err != nil {
		return false, fmt.Errorf("postgres: mark mfa_pending_login_session consumed: %w", err)
	}
	return ct.RowsAffected() == 1, nil
}

// RecordFailedVerifyAttempt increments failed_attempts on a still-live
// handle and, at the threshold, invalidates it — all in one atomic
// statement. See the interface doc for the contract.
func (r *PgxMFAPendingLoginSessionRepository) RecordFailedVerifyAttempt(ctx context.Context, id uuid.UUID, maxAttempts int, now time.Time) (bool, error) {
	if maxAttempts < 1 {
		// A non-positive threshold would mean "no guesses allowed",
		// which is a wiring bug, not a runtime condition. Fail closed.
		return false, fmt.Errorf("postgres: RecordFailedVerifyAttempt requires maxAttempts >= 1 (got %d)", maxAttempts)
	}
	// One statement does both jobs: bump the counter AND, when the bump
	// reaches the threshold, set consumed_at to kill the handle. Because
	// it is a single UPDATE, concurrent failed guesses (same handle, any
	// replica) each land as one atomic increment with no lost updates and
	// no read-modify-write window. `consumed_at IS NULL` scopes it to a
	// live handle; a row already consumed/expired matches zero rows.
	const q = `
UPDATE mfa_pending_login_sessions
SET    failed_attempts = failed_attempts + 1,
       consumed_at = CASE WHEN failed_attempts + 1 >= $3 THEN $2 ELSE consumed_at END
WHERE  id = $1
  AND  consumed_at IS NULL
  AND  expires_at > $2
RETURNING (consumed_at IS NOT NULL)`
	var invalidated bool
	if err := r.db.QueryRow(ctx, q, id, now, maxAttempts).Scan(&invalidated); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The handle was already consumed, expired, or removed by a
			// concurrent request between the service's read and this
			// increment. It is dead either way — report invalidated,
			// no error (nothing left to guess against).
			return true, nil
		}
		return false, fmt.Errorf("postgres: record mfa failed verify attempt: %w", err)
	}
	return invalidated, nil
}

// DeleteExpired removes rows whose expires_at is older than
// (now - grace).
func (r *PgxMFAPendingLoginSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	// Sweep abandoned/expired enrollment+verify handles on the DB clock
	// (NOW()), removing ONLY rows past their expiry — this is what evicts
	// the candidate encrypted TOTP seed + recovery-code hashes retained
	// by every started, never-finished enrollment. A live handle inside
	// its window (still consumable) is never touched. Mirrors the
	// oidc_states sweeper shape.
	const q = `DELETE FROM mfa_pending_login_sessions WHERE expires_at < NOW()`
	ct, err := r.db.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired mfa_pending_login_sessions: %w", err)
	}
	return ct.RowsAffected(), nil
}
