package domain

import (
	"time"

	"github.com/google/uuid"
)

type IdentityProviderType string

const (
	IDPTypeLDAP IdentityProviderType = "ldap"
	IDPTypeAD   IdentityProviderType = "ad"
	IDPTypeOIDC IdentityProviderType = "oidc"
)

// IdentityProvider represents a configuration for an external authentication source
type IdentityProvider struct {
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Config         ProviderConfig
	Type           IdentityProviderType
	Name           string
	Slug           string
	Priority       int
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Active         bool
}

// ProviderConfig maps the JSONB configuration column
type ProviderConfig struct {
	AttributeMapping      map[string]string
	ClaimMapping          map[string]string
	TLSOptions            *TLSOptions
	IssuerURL             string
	ClientSecretEncrypted string
	UserFilter            string
	BindPasswordEncrypted string
	BindDN                string
	Host                  string
	ClientID              string
	BaseDN                string
	SyncSchedule          string
	Scopes                []string
	EmailDomains          []string
	RedirectURIs          []string
	Port                  int
	PKCERequired          bool
	AllowExternalDomains  bool
	SyncEnabled           bool
}

// TLSOptions for LDAP connections
type TLSOptions struct {
	InsecureSkipVerify bool
	DisableTLS         bool // Force plaintext (use with caution)
}

// ExternalUser represents a user resolved from an external identity provider
// Normalized format for creating/updating local users via JIT
type ExternalUser struct {
	DN             string // LDAP DN, empty for OIDC
	Email          string
	Name           string
	ExternalID     string // The stable ID (entryUUID for LDAP, issuer|sub for OIDC) - Source of Truth
	Issuer         string // For OIDC, used for validation
	OrganizationID uuid.UUID
	EmailVerified  bool // Trusted verification status from IdP
	// UpstreamACR is the verbatim `acr` claim from the upstream IdP's
	// ID token (when present and parsable as a string). Empty when the
	// upstream IdP did not assert an acr value. The Identuum ladder rung
	// stamped on the local session is derived from this string by the
	// service layer (see auth.MapUpstreamACRToLadder).
	UpstreamACR string
}
