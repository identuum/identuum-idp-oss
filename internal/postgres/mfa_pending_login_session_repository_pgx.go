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
	if row.Kind != domain.MFAPendingKindEnroll && row.Kind != domain.MFAPendingKindVerify && row.Kind != domain.MFAPendingKindPasswordChange {
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
	return r.getOne(ctx, q, id)
}

// GetLatestLiveEnroll returns the user's newest enrol-kind row that holds a
// candidate secret and is neither consumed nor expired at now (OSS-HARDEN-1).
// user_id is indexed (0017); ids are UUIDv7, so id breaks a created_at tie in
// creation order.
func (r *PgxMFAPendingLoginSessionRepository) GetLatestLiveEnroll(ctx context.Context, userID uuid.UUID, now time.Time) (*domain.MFAPendingLoginSession, error) {
	const q = `
SELECT id, user_id, kind, secret, recovery_codes, remember_me, created_at, expires_at, consumed_at, failed_attempts
FROM   mfa_pending_login_sessions
WHERE  user_id = $1 AND kind = 'enroll' AND secret IS NOT NULL AND consumed_at IS NULL AND expires_at > $2
ORDER  BY created_at DESC, id DESC
LIMIT  1`
	return r.getOne(ctx, q, userID, now)
}

func (r *PgxMFAPendingLoginSessionRepository) getOne(ctx context.Context, q string, args ...any) (*domain.MFAPendingLoginSession, error) {
	var out domain.MFAPendingLoginSession
	var kind string
	var secret *string
	var codesJSON []byte
	if err := r.db.QueryRow(ctx, q, args...).Scan(
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

// CountRecentFailedVerifyAttempts sums failed_attempts over the user's
// verify-kind handles created at or after since. See the interface doc.
func (r *PgxMFAPendingLoginSessionRepository) CountRecentFailedVerifyAttempts(ctx context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error) {
	const q = `
SELECT COALESCE(SUM(failed_attempts), 0)::int,
       MIN(created_at) FILTER (WHERE failed_attempts > 0)
FROM   mfa_pending_login_sessions
WHERE  user_id = $1
  AND  kind = 'verify'
  AND  created_at >= $2`
	var n int
	var oldest *time.Time
	if err := r.db.QueryRow(ctx, q, userID, since).Scan(&n, &oldest); err != nil {
		return 0, time.Time{}, fmt.Errorf("postgres: count recent failed mfa verify attempts: %w", err)
	}
	if oldest == nil {
		return n, time.Time{}, nil
	}
	return n, *oldest, nil
}

// DeleteForUser removes every pending sign-in row of the user (FUNC-M3).
func (r *PgxMFAPendingLoginSessionRepository) DeleteForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	const q = `DELETE FROM mfa_pending_login_sessions WHERE user_id = $1`
	cmd, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete mfa pending sessions of a user: %w", err)
	}
	return cmd.RowsAffected(), nil
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
	//
	// A verify handle that recorded wrong codes is KEPT for
	// repository.MFAFailedAttemptRetention after creation: those counts are
	// the per-user wrong-code evidence CountRecentFailedVerifyAttempts sums,
	// and a handle expires (5 minutes) well before that window does. A verify
	// row carries no secret material, so keeping it holds nothing sensitive.
	const q = `
DELETE FROM mfa_pending_login_sessions
WHERE  expires_at < NOW()
  AND  NOT (kind = 'verify'
            AND failed_attempts > 0
            AND created_at >= NOW() - make_interval(secs => $1))`
	ct, err := r.db.Exec(ctx, q, repository.MFAFailedAttemptRetention.Seconds())
	if err != nil {
		return 0, fmt.Errorf("postgres: delete expired mfa_pending_login_sessions: %w", err)
	}
	return ct.RowsAffected(), nil
}
