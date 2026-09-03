package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AgentCommunicationTokenRepository persists the jti → authorization binding
// of every issued participant token (AYGHU-4). Any error is a store failure
// the caller surfaces as unavailability.
type AgentCommunicationTokenRepository interface {
	// Insert records an issued token; a duplicate jti is an error.
	Insert(ctx context.Context, t *domain.AgentCommunicationToken) error

	// ListActiveByAuthorization returns the tokens of authorizationID whose
	// expires_at is after now (the ones a revocation must still reach).
	ListActiveByAuthorization(ctx context.Context, authorizationID uuid.UUID, now time.Time) ([]domain.AgentCommunicationToken, error)

	// DeleteExpiredBefore prunes rows whose expires_at < cutoff.
	DeleteExpiredBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
