package domain

import (
	"time"

	"github.com/google/uuid"
)

// EmailVerification represents a single-use email-verification token row.
//
// The raw token shown to the operator is NEVER persisted; only its
// SHA-256 hash lives here (TokenHash is the table primary key, so the
// hash also serves as the consume-side lookup key).
//
// Single-use semantics:
//   - Consume sets UsedAt to a non-nil timestamp.
//   - The service layer rejects rows with UsedAt != nil OR expired.
//   - DeleteExpired sweeps rows past ExpiresAt at maintenance time;
//     the service layer's expiry check is still the authoritative gate
//     so a stale row that has not yet been swept cannot be replayed.
//
// Multi-token-per-user:
//   - A user may have multiple in-flight verifications (e.g. operator
//     clicks "resend verification" twice within 30 seconds). The
//     PRIMARY KEY on token_hash gives each its own row; the latest
//     wins because the consume-side lookup is by token_hash, not by
//     user_id. Stale rows expire naturally via the 24-hour TTL.
type EmailVerification struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
	TokenHash string
	UserID    uuid.UUID
}

// IsValid reports whether the row may be consumed at `now`.
// A row is valid when it has not been used AND has not expired.
// The caller (service layer) MUST inject now — the model never
// reads the system clock so tests can drive every branch.
func (e *EmailVerification) IsValid(now time.Time) bool {
	if e.UsedAt != nil {
		return false
	}
	return now.Before(e.ExpiresAt)
}
