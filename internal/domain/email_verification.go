package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
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
//
// Address binding (OSS-0912-C2-FIX): AddressHash is EmailAddressHash of the
// address the link was mailed to. A link proves only that address: a row
// whose AddressHash differs from the user's current address, or is empty (a
// row written before migration 0054), proves nothing.
type EmailVerification struct {
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UsedAt      *time.Time
	TokenHash   string
	AddressHash string
	UserID      uuid.UUID
}

// EmailAddressHash is the hex SHA-256 of the address, lower-cased and
// trimmed, as a verification row stores it.
func EmailAddressHash(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// ProvesAddress reports whether the row was mailed to email.
func (e *EmailVerification) ProvesAddress(email string) bool {
	if e.AddressHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(e.AddressHash), []byte(EmailAddressHash(email))) == 1
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
