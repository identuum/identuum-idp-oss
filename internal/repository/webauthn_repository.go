package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ErrWebAuthnCredentialNotFound is returned from
// WebAuthnCredentialRepository.GetByCredentialID when the supplied
// raw credential id has no live row. The service layer collapses
// this onto an opaque login failure so the wire response cannot
// disambiguate "credential never existed" from "credential was
// deleted".
var ErrWebAuthnCredentialNotFound = errors.New("webauthn credential not found")

// WebAuthnCredentialRepository defines data access for passkeys
type WebAuthnCredentialRepository interface {
	// Create stores a new credential
	Create(ctx context.Context, cred *domain.WebAuthnCredential) (*domain.WebAuthnCredential, error)

	// GetByCredentialID retrieves a credential by its raw ID (from the authenticator)
	// OrganizationID is implicit via the join or checks in service, but credentials are global unique by ID usually.
	// However, we enforce tenant isolation where possible.
	GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error)

	// ListByUser retrieves all credentials for a user
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error)

	// UpdateSignCount updates the signature counter and last used timestamp
	UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32) error

	// UpdateLastUsed updates just the timestamp (e.g. if counter unused)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error

	// Delete removes a credential
	Delete(ctx context.Context, id uuid.UUID) error

	// UpdateCloneWarning updates the clone warning flag
	UpdateCloneWarning(ctx context.Context, id uuid.UUID, warning bool) error
}
