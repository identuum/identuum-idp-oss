package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OAuthAuthorizationCodeRepository persists rows in
// oauth_authorization_codes. Distinct from the legacy
// AuthCodeRepository (which the monolith uses); the new repo is
// hash-only with a consumed_at lifecycle.
type OAuthAuthorizationCodeRepository interface {
	// Insert plants a fresh row. Returns the persisted record.
	Insert(ctx context.Context, code *domain.OAuthAuthorizationCode) error

	// GetActiveByCodeHash returns the row whose code_hash matches
	// AND consumed_at IS NULL AND expires_at > now. Used by
	// Consume to short-circuit reuse / expired / unknown
	// attempts. Returns (nil, nil) for any not-active state.
	GetActiveByCodeHash(ctx context.Context, codeHash string, now time.Time) (*domain.OAuthAuthorizationCode, error)

	// GetByCodeHashAnyState returns the row whose code_hash matches
	// REGARDLESS of consumed_at and expires_at, or (nil, nil) when no such
	// code was ever issued. It exists so the consume path can tell "this
	// code was already used" apart from "this code never existed" — a
	// distinction GetActiveByCodeHash deliberately erases by returning
	// (nil, nil) for both. RFC 6819 §5.2.1.1 treats the first as evidence
	// of compromise and the second as an ordinary bad request (P0-1b).
	GetByCodeHashAnyState(ctx context.Context, codeHash string) (*domain.OAuthAuthorizationCode, error)

	// MarkConsumed atomically flips consumed_at from NULL to `at` on
	// the row identified by id, but ONLY while it is still active
	// (consumed_at IS NULL). It returns won=true when THIS call
	// performed the flip (exactly one row affected) and won=false when
	// the row was already consumed — a concurrent caller won the race
	// or the code is being replayed. Callers MUST treat won=false as a
	// rejected consume: this is the atomic single-use gate for the
	// authorization_code grant, so the command tag can never be
	// silently discarded.
	MarkConsumed(ctx context.Context, id uuid.UUID, at time.Time) (won bool, err error)

	// DeleteExpiredBefore prunes rows whose expires_at is at or
	// before the supplied cutoff. Returns the deleted-row count.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
