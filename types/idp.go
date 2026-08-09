package types

import (
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// CreateIdentityProviderRequest defines the payload for creating an IDP
type CreateIdentityProviderRequest struct {
	Config   map[string]any              `json:"config" binding:"required"`
	Type     domain.IdentityProviderType `json:"type" binding:"required,oneof=ldap ad oidc"`
	Name     string                      `json:"name" binding:"required"`
	Slug     string                      `json:"slug" binding:"required"`
	Priority int                         `json:"priority"`
}

// UpdateIdentityProviderRequest defines the payload for updating an IDP
type UpdateIdentityProviderRequest struct {
	Priority *int           `json:"priority"`
	Active   *bool          `json:"active"`
	Config   map[string]any `json:"config"`
	Name     string         `json:"name"`
	Slug     string         `json:"slug"`
}

// IdentityProviderResponse defines the API response for an IDP
type IdentityProviderResponse struct {
	IdentityProvider *IdentityProviderInfo `json:"identity_provider,omitempty"`
	Message          string                `json:"message"`
	Success          bool                  `json:"success"`
}

// IdentityProviderListResponse defines the API response for listing IDPs
type IdentityProviderListResponse struct {
	Message           string                 `json:"message"`
	IdentityProviders []IdentityProviderInfo `json:"identity_providers"`
	Count             int                    `json:"count"`
	Success           bool                   `json:"success"`
}

// IdentityProviderInfo represents the public view of an IDP
type IdentityProviderInfo struct {
	CreatedAt      time.Time                   `json:"created_at"`
	UpdatedAt      time.Time                   `json:"updated_at"`
	Config         ProviderConfig              `json:"config"`
	Type           domain.IdentityProviderType `json:"type"`
	Name           string                      `json:"name"`
	Slug           string                      `json:"slug"`
	Priority       int                         `json:"priority"`
	ID             uuid.UUID                   `json:"id"`
	OrganizationID uuid.UUID                   `json:"organization_id"`
	Active         bool                        `json:"active"`
}

// ProviderConfigDTO defines the JSON structure for IDP configuration
type ProviderConfig struct {
	TLSOptions           *TLSOptionsDTO    `json:"tls_options,omitempty"`
	AttributeMapping     map[string]string `json:"attribute_mapping,omitempty"`
	ClaimMapping         map[string]string `json:"claim_mapping,omitempty"`
	UserFilter           string            `json:"user_filter,omitempty"`
	Host                 string            `json:"host,omitempty"`
	BaseDN               string            `json:"base_dn,omitempty"`
	IssuerURL            string            `json:"issuer_url,omitempty"`
	ClientID             string            `json:"client_id,omitempty"`
	SyncSchedule         string            `json:"sync_schedule,omitempty"`
	BindDN               string            `json:"bind_dn,omitempty"`
	EmailDomains         []string          `json:"email_domains,omitempty"`
	Scopes               []string          `json:"scopes,omitempty"`
	RedirectURIs         []string          `json:"redirect_uris,omitempty"`
	Port                 int               `json:"port,omitempty"`
	PKCERequired         bool              `json:"pkce_required,omitempty"`
	AllowExternalDomains bool              `json:"allow_external_domains"`
	SyncEnabled          bool              `json:"sync_enabled"`
}

type TLSOptionsDTO struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	DisableTLS         bool `json:"disable_tls"`
}
