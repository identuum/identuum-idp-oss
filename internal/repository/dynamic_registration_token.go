package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrDynamicRegistrationTokenNotFound is the sentinel returned
// when a lookup hits no row. The service layer maps this to a
// generic "invalid_token" error envelope so the caller cannot
// distinguish "no such token" from "wrong scope" — same opaque
// 401 response either way.
var ErrDynamicRegistrationTokenNotFound = errors.New("repository: dynamic registration token not found")

// ErrDynamicRegistrationTokenInactive is the sentinel returned by
// ConsumeByHash when the token is found but is revoked, expired,
// or has reached its MaxUses ceiling. Service layer maps to the
// same opaque invalid_token error as ErrDynamicRegistrationTokenNotFound.
var ErrDynamicRegistrationTokenInactive = errors.New("repository: dynamic registration token inactive")

// DynamicRegistrationTokenRepository persists DCR initial access
// tokens (IATs) and provides the atomic consume operation that
// the DCR handler uses to gate registration when a bearer IAT
// accompanies the request.
//
// Insert / List / Revoke are admin-facing operations; Bootstrap
// gating is enforced at the HTTP layer via site_admin guards.
// ConsumeByHash is the load-bearing path: it MUST atomically
// (a) verify the row is active at consume time, (b) increment
// uses_count by 1, and (c) return the updated row to the caller
// — all inside a single SQL round-trip so two concurrent DCR
// callers cannot both pass the IsActive gate.
type DynamicRegistrationTokenRepository interface {
	// Insert persists a new IAT. token.ID, token.TokenHash, and
	// token.ExpiresAt are required. Returns the persisted row
	// (with CreatedAt + UpdatedAt set).
	Insert(ctx context.Context, token *domain.DynamicRegistrationToken) (*domain.DynamicRegistrationToken, error)

	// GetByID returns the row identified by id, or
	// ErrDynamicRegistrationTokenNotFound when absent.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.DynamicRegistrationToken, error)

	// List returns IAT rows in created_at-DESC order. The safe
	// projection guarantee: the returned rows MUST NOT carry the
	// token_hash field populated; the repository implementations
	// scrub it before returning so a list-call cannot leak the
	// hash even to a site_admin actor.
	List(ctx context.Context) ([]*domain.DynamicRegistrationToken, error)

	// Revoke sets revoked_at = now on the row identified by id.
	// Returns ErrDynamicRegistrationTokenNotFound when no row
	// matches. Idempotent: re-revoking a revoked row is a no-op
	// and returns nil.
	Revoke(ctx context.Context, id uuid.UUID, at time.Time) error

	// ConsumeByHash atomically looks up the row by token_hash,
	// verifies active-at-time, increments uses_count, and returns
	// the updated row. Returns ErrDynamicRegistrationTokenNotFound
	// when no row matches the hash, and
	// ErrDynamicRegistrationTokenInactive when the row exists but
	// fails the activeness predicate (revoked/expired/exhausted).
	//
	// The returned row's TokenHash field MUST be empty so the
	// caller cannot accidentally re-emit the hash downstream.
	ConsumeByHash(ctx context.Context, tokenHash string, at time.Time) (*domain.DynamicRegistrationToken, error)

	// DeleteExpiredBefore prunes rows whose expires_at is at or
	// before cutoff. Returns the deleted-row count for
	// observability.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
