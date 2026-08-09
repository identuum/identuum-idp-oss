package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ClientRepository defines storage operations for OAuth2 Clients
type ClientRepository interface {
	RegisterClient(ctx context.Context, client *domain.Client) error
	GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	Delete(ctx context.Context, id uuid.UUID, orgID *uuid.UUID) error
	List(ctx context.Context, pagination Pagination, orgID *uuid.UUID) ([]*domain.Client, int, error)
	// ListByServiceAccountID returns the OAuth clients linked to a given
	// service account within an organization. The codebase treats SA↔client
	// as 1:1 (see MCP/SCIM bootstrap flows and GenerateTokensForClient's
	// invariant check), but the oauth_clients.service_account_id FK has no
	// UNIQUE constraint at the schema level. Callers MUST enforce the
	// exactly-one invariant and surface a dedicated error if the query
	// returns more than one row, rather than silently iterating. The impl
	// applies LIMIT 2 so cardinality violations are detectable without
	// unbounded scans.
	ListByServiceAccountID(ctx context.Context, orgID uuid.UUID, saID uuid.UUID) ([]*domain.Client, error)
	SaveConsent(ctx context.Context, consent *domain.Consent) error
	GetConsent(ctx context.Context, userID, clientID uuid.UUID, apiResourceID *uuid.UUID) (*domain.Consent, error)
}
