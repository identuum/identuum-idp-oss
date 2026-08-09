package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OAuthConsentRepository persists OIDC consent rows.
type OAuthConsentRepository interface {
	// Upsert inserts a new active row OR flips a revoked row back
	// active with the supplied scope. Conflict resolution is on
	// (user_id, client_id, audience). Returns the persisted row.
	Upsert(ctx context.Context, c *domain.OAuthConsent) (*domain.OAuthConsent, error)

	// GetActive returns the (user, client, audience) row when it
	// exists AND revoked_at IS NULL. Returns (nil, nil) on a
	// resolved absence (not found / revoked).
	GetActive(ctx context.Context, userID uuid.UUID, clientID, audience string) (*domain.OAuthConsent, error)

	// Revoke soft-deletes the (user, client, audience) row by
	// setting revoked_at = now. No-op when the row is absent.
	Revoke(ctx context.Context, userID uuid.UUID, clientID, audience string, at time.Time) error
}
