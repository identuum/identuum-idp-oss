package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// OrganizationClaim represents a one-time use claim token for bootstrapping an empty organization shell
// This is the NEW pattern - pure domain model without database concerns
type OrganizationClaim struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	TokenHash string
	// TargetEmail is the normalized (lowercase, trimmed) email the URL is bound
	// to. Empty for no-email tokens (EmailBound=false) and on legacy rows.
	TargetEmail    string
	ID             uuid.UUID
	OrganizationID uuid.UUID
	AttemptCount   int // number of failed password attempts recorded against this claim
	// EmailBound mirrors the organization_claims.email_bound column. When true
	// the claim is consumable only with a submitted email matching TargetEmail.
	// When false (manual-delivery / out-of-band token) the claimant supplies
	// any valid email at consume time and that email is used for the new admin.
	// Migration 0013 added the column with DEFAULT TRUE so legacy rows remain
	// bound (and reject consume when TargetEmail is empty).
	EmailBound bool
}

// Validate performs business logic validation on the OrganizationClaim
func (c *OrganizationClaim) Validate() error {
	if c.OrganizationID == uuid.Nil {
		return errors.New("organization_id is required")
	}

	if c.TokenHash == "" {
		return errors.New("token_hash is required")
	}

	return nil
}

// IsExpired checks if the claim token has expired.
// now must be injected by the caller (service layer).
func (c *OrganizationClaim) IsExpired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}

// IsMaxAttemptsReached returns true if the claim has exhausted all allowed
// password attempts. Uses the domain constant as the single source of truth.
func (c *OrganizationClaim) IsMaxAttemptsReached() bool {
	return c.AttemptCount >= ClaimMaxPasswordAttempts
}
