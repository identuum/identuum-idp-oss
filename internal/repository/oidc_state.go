package repository

import (
	"context"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OIDCStateRepository defines persistence for OIDC states
type OIDCStateRepository interface {
	// Create persists a new OIDC state
	Create(ctx context.Context, state *domain.OIDCState) error

	// Get retrieves a state by its unique string key
	Get(ctx context.Context, state string) (*domain.OIDCState, error)

	// ConsumeByState atomically deletes the state row and returns it in a
	// SINGLE statement (DELETE … WHERE state = $1 RETURNING …). The row is
	// returned ONLY to the caller whose DELETE actually removed it; every
	// other concurrent caller — and any replay of an already-consumed,
	// never-existent, or expired-and-swept state — gets (nil, nil). This
	// returned-row-is-the-proof gate is what makes upstream-login state
	// single-use; callers MUST reject a nil row (no session, no token
	// exchange). Expiry and provider-match are still enforced by the caller
	// on the returned row. Replaces the old GetAndLock+Delete, whose
	// SELECT … FOR UPDATE ran in an implicit pool transaction that released
	// the lock immediately (so the state was not single-use under
	// concurrency).
	ConsumeByState(ctx context.Context, state string) (*domain.OIDCState, error)

	// Delete removes a state
	Delete(ctx context.Context, state string) error

	// DeleteExpired prunes every oidc_states row whose expires_at is in the
	// past, returning the number of rows removed. Called periodically by the
	// ephemeral-table cleanup driver; single-use consumption already deletes
	// live rows, so this only reaps states abandoned before callback.
	DeleteExpired(ctx context.Context) (int64, error)
}
