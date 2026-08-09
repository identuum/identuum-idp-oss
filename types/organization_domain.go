package types

import (
	"time"

	"github.com/google/uuid"
)

// OrganizationDomainInfo is the wire-safe projection of one row in
// organization_domains. The struct intentionally does NOT carry
// verification_token_hash — the stored hash is service-internal and
// must never leave the API surface. The raw verification token is also
// never present here; it appears exactly once in
// OrganizationDomainChallengeResponse.
type OrganizationDomainInfo struct {
	ID                         uuid.UUID  `json:"id"`
	OrganizationID             uuid.UUID  `json:"organization_id"`
	Domain                     string     `json:"domain"`
	IsPrimary                  bool       `json:"is_primary"`
	Verified                   bool       `json:"verified"`
	VerifiedAt                 *time.Time `json:"verified_at,omitempty"`
	VerificationTokenExpiresAt *time.Time `json:"verification_token_expires_at,omitempty"`
	VerificationAttempts       int        `json:"verification_attempts"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
}

// OrganizationDomainChallenge is the DNS-TXT challenge envelope returned
// to a caller that has just minted a fresh verification token. The raw
// token appears on RecordValue (suffixed onto the deterministic
// "identuum-domain-verification=" prefix) — this is the single
// authorized exit point for token material. The bare Token field is
// also populated as a convenience for clients that prefer to read the
// raw value off a dedicated key.
type OrganizationDomainChallenge struct {
	RecordName  string    `json:"record_name"`
	RecordType  string    `json:"record_type"`
	RecordValue string    `json:"record_value"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AddOrganizationDomainRequest is the strict-JSON body for
// POST /api/v1/organizations/:id/domains. Only the domain string is
// accepted from the wire; the organization id is taken from the URL
// path and re-authorized by the service. No organization_id field is
// permitted on this body — StrictBindJSON would reject the request
// because the struct does not declare one.
type AddOrganizationDomainRequest struct {
	Domain string `json:"domain"`
}

// OrganizationDomainListResponse is the GET-list response.
type OrganizationDomainListResponse struct {
	Domains []OrganizationDomainInfo `json:"domains"`
	Count   int                      `json:"count"`
}

// OrganizationDomainResponse is the read-shape returned by every
// per-row endpoint that does NOT mint a challenge (verify, list-one,
// future GET-by-id).
type OrganizationDomainResponse struct {
	Domain OrganizationDomainInfo `json:"domain"`
}

// OrganizationDomainChallengeResponse is the single-shot envelope
// returned by POST /api/v1/organizations/:id/domains. The Challenge
// field is the ONLY place the raw verification token appears in the
// API surface; every other response shape on this resource hides it.
type OrganizationDomainChallengeResponse struct {
	Domain    OrganizationDomainInfo      `json:"domain"`
	Challenge OrganizationDomainChallenge `json:"challenge"`
}

// OrganizationDomainDeleteResponse is the response shape for the
// DELETE endpoint. We intentionally return a structured body rather
// than 204-no-content so the caller can chain on the JSON envelope
// pattern the rest of the org-scoped surface uses.
type OrganizationDomainDeleteResponse struct {
	Deleted bool `json:"deleted"`
}

// OrganizationDomainSetPrimaryResponse is the response shape for the
// set-primary endpoint.
type OrganizationDomainSetPrimaryResponse struct {
	Primary bool `json:"primary"`
}
