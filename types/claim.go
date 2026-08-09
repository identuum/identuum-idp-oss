package types

import "time"

// GenerateClaimRequest represents the JSON payload to generate a new claim (admin only)
type GenerateClaimRequest struct {
	// RecipientEmail is the email address the claim URL will be bound to.
	// Required: the URL will only be consumable by this exact email address.
	// If SMTP is configured the link is also emailed automatically.
	RecipientEmail string `json:"recipient_email"`
}

// GenerateClaimResponse represents the response containing the one-time claim URL
type GenerateClaimResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	ClaimURL  string    `json:"claim_url"`
	// EmailSent is true if the claim link was successfully emailed to the recipient.
	EmailSent bool `json:"email_sent"`
}

// ValidateClaimResponse represents the pre-flight check response
type ValidateClaimResponse struct {
	OrganizationName string `json:"organization_name,omitempty"`
	// TargetEmail is the email address the claim URL is bound to.
	// Present when Valid is true; allows the UI to pre-fill and display
	// the intended email to the user (read-only — cannot be changed).
	TargetEmail string `json:"target_email,omitempty"`
	Valid       bool   `json:"valid"`
}

// ConsumeClaimRequest represents the unauthenticated payload to claim an organization
type ConsumeClaimRequest struct {
	Token    string `json:"token" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name     string `json:"name,omitempty"`
}

// ConsumeClaimResponse represents the success response after claiming
type ConsumeClaimResponse struct {
	Success bool `json:"success"`
}

// ConsumeClaimMaxAttemptsResponse is returned when the claim token is burned
// due to too many invalid password attempts. The token is permanently invalidated.
type ConsumeClaimMaxAttemptsResponse struct {
	Success           bool   `json:"success"`
	Message           string `json:"message"`
	AttemptsExhausted bool   `json:"attempts_exhausted"`
}

// ConsumeClaimPasswordViolationResponse is returned when the submitted password
// fails policy validation but the claim token is still valid. AttemptsRemaining
// tells the frontend how many more attempts are allowed before the token burns.
type ConsumeClaimPasswordViolationResponse struct {
	Success           bool   `json:"success"`
	Message           string `json:"message"`
	AttemptsRemaining int    `json:"attempts_remaining"`
}
