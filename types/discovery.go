package types

import (
	"github.com/google/uuid"
)

// OrganizationPublicConfig represents the public security configuration exposed to the frontend
type OrganizationPublicConfig struct {
	Name              string          `json:"name"`
	Slug              string          `json:"slug"`
	Domain            string          `json:"domain"`
	AuthPolicy        string          `json:"auth_policy"`
	LoginURL          string          `json:"login_url"`
	RequestID         string          `json:"request_id,omitempty"`
	IdentityProviders []PublicIDPInfo `json:"identity_providers"`
}

// PublicIDPInfo represents safe-to-expose details about an Identity Provider
type PublicIDPInfo struct {
	Type         string    `json:"type"`
	Name         string    `json:"name"`
	LoginURL     string    `json:"login_url"`
	EmailDomains []string  `json:"email_domains"`
	ID           uuid.UUID `json:"id"`
}

// EmailDiscoveryResult is the response type for GET /api/v1/auth/email-discovery.
//
// Status values:
//   - "redirect"        — exactly one active OIDC IdP; RedirectURL is set
//   - "choice_required" — multiple active IdPs; IDPs list is set
//   - "no_route"        — org found but no IdP with a redirect URL (local auth only); LoginURL is set
//   - "not_found"       — no org matches the email domain
//   - "invalid_email"   — email failed basic format validation
type EmailDiscoveryResult struct {
	Status      string          `json:"status"`
	RedirectURL string          `json:"redirect_url,omitempty"`
	LoginURL    string          `json:"login_url,omitempty"`
	IDPs        []PublicIDPInfo `json:"idps,omitempty"`
}
