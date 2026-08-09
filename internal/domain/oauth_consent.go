package domain

import (
	"time"

	"github.com/google/uuid"
)

// OAuthConsent represents one remembered OIDC consent row in the
// oauth_consents table. The scope string is space-separated and
// space-normalised at the service layer; the membership test at
// /authorize time compares token-by-token.
type OAuthConsent struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	ClientID       string
	Audience       string
	Scope          string
	GrantedAt      time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IsActive reports whether the row is currently a live grant
// (revoked_at IS NULL).
func (c *OAuthConsent) IsActive() bool {
	return c != nil && c.RevokedAt == nil
}
