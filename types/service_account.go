package types

import (
	"time"

	"github.com/google/uuid"
)

// ServiceAccount represents a service account DTO
type ServiceAccount struct {
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Role           string     `json:"role"`
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	// Active is the SA lifecycle state (slice
	// identuum-20260530-service-account-active-dto-backend). True
	// when the SA can mint new client_credentials tokens via its
	// linked OAuth client; false when an org_admin has disabled it
	// via POST .../disable. The IDP's GenerateTokensForClient SA
	// lifecycle guard refuses new tokens when this is false. Already-
	// issued access tokens run to their natural expiry. Surfacing
	// this on the wire DTO lets the org-admin UI render the
	// persistent Active/Disabled badge + Enable affordance after a
	// hard reload (the prior gap documented by the UI slice
	// identuum-20260530-service-account-disable-enable-ui).
	Active bool `json:"active"`
}

// ServiceAccountWithSecret represents a service account with its associated client credentials (creation only)
type ServiceAccountWithSecret struct {
	ServiceAccount
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
