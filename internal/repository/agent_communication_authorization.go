package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// AgentCommunicationAuthorizationRepository persists the AYGHU-1
// aggregate: one authorization row plus exactly two participant rows.
//
// Error contract (AUTH-503 doctrine): the ONLY typed verdict a read
// returns for an absent row is domain.ErrAgentCommunicationAuthorizationNotFound;
// every other error is a store failure the caller must surface as
// unavailability, never as a verdict.
type AgentCommunicationAuthorizationRepository interface {
	// Create persists the authorization and BOTH participant rows in ONE
	// transaction; a failure on any row leaves nothing behind. The
	// aggregate must already be validated (domain.Validate).
	Create(ctx context.Context, a *domain.AgentCommunicationAuthorization) error

	// GetByID returns the authorization with its two participants, scoped
	// to organizationID. An absent row and a row of another organization
	// are indistinguishable (ErrAgentCommunicationAuthorizationNotFound).
	GetByID(ctx context.Context, organizationID, id uuid.UUID) (*domain.AgentCommunicationAuthorization, error)

	// ListByOrganization returns every authorization of the organization
	// (any status), newest first, each with its participants.
	ListByOrganization(ctx context.Context, organizationID uuid.UUID) ([]*domain.AgentCommunicationAuthorization, error)

	// Revoke stamps revoked_at/revoked_by/revocation_reason on the row
	// when it is not yet revoked. It returns true when THIS call revoked
	// the row and false when the row is absent, of another organization,
	// or already revoked (revocation is terminal: the first stamp wins).
	Revoke(ctx context.Context, organizationID, id, revokedBy uuid.UUID, reason *string, at time.Time) (bool, error)

	// HasLiveParticipant reports whether an authorization of organizationID
	// that is LIVE at `now` (not revoked, not yet expired) names
	// serviceAccountID as one of its two participants
	// (THE-OWNERLESS-ACCOUNT). Ownership of a participating agent identity
	// cannot be transferred while such an authorization stands: the
	// same-owner rule was judged against the owner of record, and issuance
	// re-checks it, so a silent transfer would strand a live session.
	HasLiveParticipant(ctx context.Context, organizationID, serviceAccountID uuid.UUID, now time.Time) (bool, error)
}
