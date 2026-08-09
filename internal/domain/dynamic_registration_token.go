package domain

import (
	"time"

	"github.com/google/uuid"
)

// DynamicRegistrationToken is an RFC 7591 §2.1 initial access token
// (IAT) that gates dynamic client registration when the operator
// does not want to surface DCR to anonymous callers.
//
// Storage shape: the raw token bytes are NEVER persisted. Only a
// SHA-256 hash (TokenHash) is kept; the raw token is returned to
// the operator exactly once at issuance.
//
// Policy carried by the row:
//
//   - OrganizationID (nullable): when present, the registered
//     client's OrganizationID MUST equal this value.
//   - AllowedGrantTypes (empty=any): the DCR request's grant_types
//     MUST be a subset.
//   - AllowedTokenEndpointAuthMethods (empty=any): the DCR
//     request's token_endpoint_auth_method MUST be a member.
//   - ExpiresAt: past = automatic invalidation.
//   - MaxUses (0=unlimited): caps the number of successful DCR
//     registrations the token can authorise.
//   - UsesCount: incremented on each consume; consume rejects when
//     UsesCount >= MaxUses (with MaxUses > 0).
//   - RevokedAt: non-nil = manually revoked. Highest priority.
type DynamicRegistrationToken struct {
	ID                              uuid.UUID
	TokenHash                       string
	OrganizationID                  *uuid.UUID
	AllowedGrantTypes               []string
	AllowedTokenEndpointAuthMethods []string
	ExpiresAt                       time.Time
	MaxUses                         int
	UsesCount                       int
	RevokedAt                       *time.Time
	CreatedByUserID                 *uuid.UUID
	Description                     string
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
}

// IsActive reports whether the token can authorise a fresh DCR
// registration call at `at`. Returns false on revoked, expired,
// or fully-consumed (MaxUses > 0 && UsesCount >= MaxUses) tokens.
//
// IsActive is a pure read-only check — it does NOT decrement or
// consume. The atomic consume happens at the repository layer.
func (t *DynamicRegistrationToken) IsActive(at time.Time) bool {
	if t == nil {
		return false
	}
	if t.RevokedAt != nil {
		return false
	}
	if !t.ExpiresAt.IsZero() && !at.Before(t.ExpiresAt) {
		return false
	}
	if t.MaxUses > 0 && t.UsesCount >= t.MaxUses {
		return false
	}
	return true
}

// IsValid retains the legacy contract for any caller written
// before MaxUses landed. It is equivalent to IsActive(time.Now())
// for single-use tokens but is kept here so existing helpers
// continue to compile while the broader DCR IAT slice rolls out.
func (t *DynamicRegistrationToken) IsValid() bool {
	return t.IsActive(time.Now())
}
