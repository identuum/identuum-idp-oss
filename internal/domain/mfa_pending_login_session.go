package domain

import (
	"time"

	"github.com/google/uuid"
)

// MFAPendingLoginSession is the OSS short-lived pending-MFA login
// state created when a correct-password login lands on a path that
// cannot yet issue a full session. Two kinds:
//
//   - MFAPendingKindEnroll — the authenticated user must enrol a
//     TOTP secret before login can complete. The candidate Secret +
//     RecoveryCodes are populated by /api/v1/auth/login/mfa/enroll/initiate
//     and consumed by /api/v1/auth/login/mfa/enroll/complete.
//
//   - MFAPendingKindVerify — the authenticated user already has a
//     TOTP secret enrolled and must supply a TOTP code via
//     /api/v1/auth/login/mfa before login can complete. Secret +
//     RecoveryCodes are nil for this kind (the user's persisted
//     MFASecret is consulted at verify time).
//
// Persistence:
//
//   - ID is the OPAQUE handle returned to the client (UUIDv7).
//   - Secret + RecoveryCodes are POPULATED IN-PLACE by /initiate so
//     /complete can verify against them without re-deriving.
//   - ConsumedAt enforces single-use; once set, the row cannot be
//     redeemed again.
//   - ExpiresAt is enforced by the service (CanBeUsed) and by the
//     sweeper that removes rows past the grace window.
//
// SAFETY: Secret + RecoveryCodes are credential material. They must
// NEVER be logged, never appear in audit metadata, never echo into
// error messages. Per-row read paths in the repository return them
// only to in-process callers (service layer); the HTTP handler
// returns them ONCE in the response body for the enrolment-initiate
// QR ceremony and that is the only path the client ever sees the
// secret bytes.
type MFAPendingLoginSession struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Kind          MFAPendingKind
	Secret        *string  // populated only when Kind=enroll and /initiate has run
	RecoveryCodes []string // populated only when Kind=enroll and /initiate has run
	RememberMe    bool
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	// FailedAttempts counts wrong TOTP/recovery-code guesses made
	// against a verify-kind handle (migration 0022, P0-13). It is
	// incremented atomically by the repository on each failed verify;
	// once it reaches the service's max-attempts threshold the handle
	// is invalidated (consumed_at set) in the SAME statement, so an
	// attacker holding a valid handle gets a bounded number of guesses
	// regardless of IP, replica, or restart. Zero for a fresh handle.
	FailedAttempts int
}

// MFAPendingKind identifies the finalisation path for a pending
// MFA login session.
type MFAPendingKind string

const (
	// MFAPendingKindEnroll means the user is enrolling MFA for the
	// first time; /initiate generates the candidate secret and
	// /complete persists it after TOTP verification.
	MFAPendingKindEnroll MFAPendingKind = "enroll"

	// MFAPendingKindVerify means the user is already enrolled and
	// only needs to supply a TOTP code; /api/v1/auth/login/mfa
	// consumes the row after verifying against the user's persisted
	// MFASecret.
	MFAPendingKindVerify MFAPendingKind = "verify"
)

// MFAPendingTTL is the default lifetime of a pending row. The
// service layer enforces this via ExpiresAt at creation time. The
// value is short so a forgotten-tab handle cannot be replayed days
// later; it is long enough for a typical enrolment ceremony (scan
// QR, generate first code).
const MFAPendingTTL = 5 * 60 // seconds; equals 5 minutes

// CanBeUsed reports whether the pending row is in a redeemable
// state at the supplied time. Returns false + a short reason when
// the row has been consumed, has expired, or carries the wrong
// kind (the caller MUST pass the expected kind it intends to
// finalise).
func (p *MFAPendingLoginSession) CanBeUsed(now time.Time, expectedKind MFAPendingKind) (bool, string) {
	if p == nil {
		return false, "pending session not found"
	}
	if p.ConsumedAt != nil {
		return false, "pending session already consumed"
	}
	if !p.ExpiresAt.After(now) {
		return false, "pending session expired"
	}
	if p.Kind != expectedKind {
		return false, "pending session kind mismatch"
	}
	return true, ""
}
