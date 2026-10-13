package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ServiceAccountLock is the service account a client save or create binds
// (OSS-0912-C1-FIX, OSS-0913-O9-FIX). Recheck, when not nil, receives the
// account as read under the lock, nil when no live row is left; its error
// refuses the save or create.
type ServiceAccountLock struct {
	ID      uuid.UUID
	Recheck func(sa *domain.ServiceAccount) error
}

// ClientRepository defines storage operations for OAuth2 Clients
type ClientRepository interface {
	RegisterClient(ctx context.Context, client *domain.Client) error
	// RegisterClientBound creates a client that binds a service account
	// (OSS-0913-O9-FIX): in ONE transaction it share-locks the account (FOR
	// SHARE), runs lockServiceAccount.Recheck on the account as read under
	// that lock, inserts the client and commits. A soft delete or deactivation
	// of the account that comes later waits until the create ends.
	//
	// Errors: Recheck's own error unchanged (nothing is written); an insert
	// failure as RegisterClient returns it; a failed begin, lock read or
	// commit domain.AuthStoreUnavailable. It never retries.
	RegisterClientBound(ctx context.Context, client *domain.Client, lockServiceAccount ServiceAccountLock) error
	GetClientByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	// MutateClient is the one way an existing client is changed (C1, OSS
	// v0.9.12): in ONE transaction it locks the live row, hands fn a copy of
	// it, writes fn's result back to exactly that row and commits, so two
	// saves of the same client run one after the other and neither loses the
	// other's change. prior is the row as locked, result the row as written;
	// both are returned only after the commit.
	//
	// lockServiceAccount, when not nil, is share-locked (FOR SHARE) BEFORE the
	// client (the order the organization delete takes), and its Recheck runs on
	// the account as read under that lock: the account's soft delete,
	// deactivation and every other change of it wait until this save ends.
	//
	// Errors: fn's or Recheck's own error unchanged (nothing is written); a missing or
	// deleted client domain.ErrClientNotFound; a value the database refuses
	// the database's error; anything else (lock wait cancelled or timed out,
	// deadlock, a failed begin, write or commit) domain.AuthStoreUnavailable.
	// It never retries.
	MutateClient(ctx context.Context, id uuid.UUID, lockServiceAccount *ServiceAccountLock, fn func(c *domain.Client) error) (prior, result *domain.Client, err error)
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
