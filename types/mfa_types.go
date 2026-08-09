package types

import (
	"github.com/google/uuid"
)

// ============================================================================
// MFA Types
// ============================================================================

// InitiateMFASetupResponse contains the secret and QR code URL for setting up MFA
type InitiateMFASetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

// CompleteMFASetupRequest contains the confirmation code to verify MFA setup
type CompleteMFASetupRequest struct {
	Code string `json:"code" binding:"required"`
}

// CompleteMFASetupResponse contains the recovery codes after successful setup
type CompleteMFASetupResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// CompleteMFALoginRequest contains the MFA code to complete login
type CompleteMFALoginRequest struct {
	Code      string    `json:"code" binding:"required"`
	SessionID uuid.UUID `json:"session_id" binding:"required"`
}

// DisableMFARequest contains the password to confirm MFA disable
type DisableMFARequest struct {
	Password string `json:"password" binding:"required"`
}

// InitiateMFAEnrollmentRequest requests MFA enrollment for a pending session.
type InitiateMFAEnrollmentRequest struct {
	SessionID uuid.UUID `json:"session_id" binding:"required"`
}

// InitiateMFAEnrollmentResponse contains the TOTP secret and QR code URL for enrollment.
type InitiateMFAEnrollmentResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

// CompleteMFAEnrollmentRequest carries the TOTP code that completes first-login enrollment.
type CompleteMFAEnrollmentRequest struct {
	SessionID uuid.UUID `json:"session_id" binding:"required"`
	Code      string    `json:"code" binding:"required"`
}
