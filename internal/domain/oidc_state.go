package domain

import (
	"time"

	"github.com/google/uuid"
)

// OIDCState represents the server-side state for an OIDC flow
type OIDCState struct {
	ExpiresAt             time.Time
	CreatedAt             time.Time
	State                 string
	Nonce                 string
	PKCEVerifierEncrypted string
	RedirectURI           string
	ReturnURL             string
	CodeChallengeMethod   string
	OrganizationID        uuid.UUID
	ProviderID            uuid.UUID
}
