package domain

import (
	"time"

	"github.com/google/uuid"
)

// Self-registration (D-021). users.registration_state marks a self-registrant;
// every other user has none and keeps the sign-in gate it always had.
const (
	RegistrationStatePendingApproval = "pending_approval"
	RegistrationStateActive          = "active"
)

// OrgRegistrationSettings is one organization's self-registration policy:
// Allow and RequireApproval are the existing allow_public_registration and
// require_registration_approval columns; VerifyEmail and EmailDomains came
// with migration 0043.
type OrgRegistrationSettings struct {
	Allow           bool     `json:"allow_public_registration"`
	RequireApproval bool     `json:"require_registration_approval"`
	VerifyEmail     bool     `json:"verify_email"`
	EmailDomains    []string `json:"email_domains"`
}

// PendingRegistration is a self-registrant held for an org_admin's approval.
type PendingRegistration struct {
	UserID    uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
