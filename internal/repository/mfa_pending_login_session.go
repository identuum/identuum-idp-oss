package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrMFAPendingSessionNotFound is the sentinel returned when a
// pending-MFA session lookup hits no row. The service layer maps
// this to the same opaque "invalid pending handle" response that
// the consumed / expired / wrong-kind paths produce — the wire
// never distinguishes these cases.
var ErrMFAPendingSessionNotFound = errors.New("repository: mfa pending login session not found")

// MFAPendingLoginSessionRepository is the persistence seam for the
// short-lived pending-MFA login state. Production wires
// *PgxMFAPendingLoginSessionRepository; tests stub the interface
// directly without touching the DB.
//
// SAFETY: Implementations MUST NOT log Secret + RecoveryCodes from
// rows they return; both fields are credential material consumed
// only by the in-process service + handler layer.
type MFAPendingLoginSessionRepository interface {
	// Create inserts a new pending row. The caller supplies a
	// freshly-generated ID (UUIDv7); the repository never picks
	// it server-side. Returns the row read back from the DB so
	// CreatedAt / ExpiresAt are populated with the persisted
	// values.
	Create(ctx context.Context, row *domain.MFAPendingLoginSession) (*domain.MFAPendingLoginSession, error)

	// GetByID retrieves a single row by id. Returns
	// ErrMFAPendingSessionNotFound when no row matches. Returns
	// the FULL row including Secret + RecoveryCodes when present;
	// the caller is responsible for not logging those fields.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.MFAPendingLoginSession, error)

	// UpdateSecret persists the candidate secret + recovery codes
	// onto an existing pending row. Used by /enroll/initiate to
	// store the generated material in-place so /enroll/complete
	// can verify against it without an extra round-trip. Returns
	// ErrMFAPendingSessionNotFound when no row matches the id.
	UpdateSecret(ctx context.Context, id uuid.UUID, secret string, recoveryCodes []string) error

	// MarkConsumed atomically sets consumed_at on the row IF it is
	// not yet consumed AND has not expired. Returns true when the
	// row was successfully marked (the caller has exclusive use of
	// it) and false when the row was already consumed, expired, or
	// missing. This is the single-use enforcement boundary; the
	// service layer MUST NOT trust an earlier GetByID's
	// consumed_at value because of TOCTOU.
	MarkConsumed(ctx context.Context, id uuid.UUID, now time.Time) (bool, error)

	// RecordFailedVerifyAttempt (P0-13) atomically increments
	// failed_attempts on a still-live handle and, when the incremented
	// count reaches maxAttempts, invalidates the handle by setting
	// consumed_at in the SAME statement. It is the brute-force bound on
	// MFA verification: one handle can never yield more than maxAttempts
	// wrong guesses, and the counter is DURABLE + SHARED (a Postgres row
	// every replica reads/writes; the single UPDATE serialises concurrent
	// failures with no read-modify-write window), so the bound holds
	// across IPs, replicas, and process restarts.
	//
	// Returns invalidated=true when THIS call pushed the handle to/over
	// the threshold, or when the row was already consumed/expired/missing
	// (a concurrent failure or legitimate consume already killed it —
	// either way the handle is dead). Returns a non-nil error ONLY on an
	// actual store failure; the caller MUST fail closed (reject the
	// verification) on error rather than let an uncounted guess through.
	RecordFailedVerifyAttempt(ctx context.Context, id uuid.UUID, maxAttempts int, now time.Time) (invalidated bool, err error)

	// DeleteExpired removes rows whose expires_at is past on the DB
	// clock (NOW()) — the maintenance sweep that evicts the candidate
	// encrypted TOTP seed + recovery-code hashes of abandoned,
	// never-finished enrollments. Returns the affected-row count. A live
	// handle inside its window is never removed. Safe to invoke
	// concurrently.
	DeleteExpired(ctx context.Context) (int64, error)
}
