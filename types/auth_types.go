package types

import (
	"time"

	"github.com/google/uuid"
)

// UserRole represents the role/permission level of a user within the system
type UserRole string

const (
	RoleOrgUser   UserRole = "org_user"   // Regular organization member with basic access
	RoleOrgAdmin  UserRole = "org_admin"  // Organization administrator with user management privileges
	RoleSiteAdmin UserRole = "site_admin" // Site-wide administrator with cross-organization access

	// MaxPageSize defines the maximum number of items that can be returned in a single paginated response
	// to prevent resource exhaustion from excessively large limit values (e.g., ?limit=999999999)
	MaxPageSize = 100
)

func IsValidUserRole(r string) bool {
	switch UserRole(r) {
	case RoleOrgUser, RoleOrgAdmin, RoleSiteAdmin:
		return true
	}
	return false
}

// PrincipalKind defines the derived type of the authenticated entity
type PrincipalKind string

const (
	PrincipalKindUser   PrincipalKind = "user"
	PrincipalKindClient PrincipalKind = "client"
)

// Principal represents the authenticated entity after token verification and context derivation
type Principal struct {
	ScopeSet map[string]struct{}
	Kind     PrincipalKind
	Role     UserRole
	UserID   uuid.UUID
	OrgID    uuid.UUID
}

// ErrorResponse represents a standard API error.
//
// SSOMigrationInEffect is set to true ONLY by the password-reset
// (POST /api/v1/auth/password/reset) and invitation-acceptance
// (POST /api/v1/auth/users/setup) endpoints, and ONLY when the
// presented token's tenant has auth_policy=idp_only AND at least one
// trusted assertion issuer configured (see SSOMigrationProbe, D-001).
// The flag is computed from the token's tenant — NOT from the
// requesting browser's session/host — so a user signed into tenant B
// who clicks a token from tenant A receives the flag derived from
// tenant A's IdP-registered state. The SPA uses this flag to render
// an SSO-redirect explanation page instead of the generic
// "expired token" page on those two surfaces.
//
// `omitempty` on bool hides `false`, so every other API endpoint's
// error response stays byte-identical to the pre-Rev 12 wire shape.
// Backend tests for the two surfaced endpoints MUST distinguish
// "field absent (false)" from "field present and true" at the JSON
// layer — see types/auth_types_test.go for the helper used.
type ErrorResponse struct {
	Message              string `json:"message" example:"Invalid credentials"`
	Code                 string `json:"code,omitempty" example:"ERROR_CODE_ROTATION_REQUIRED"`
	Success              bool   `json:"success" example:"false"`
	SSOMigrationInEffect bool   `json:"sso_migration_in_effect,omitempty" example:"true"`
	// ErrorKind is an optional machine-readable discriminator that lets
	// the UI classify an error without parsing the human-facing
	// `Message`. Only a small allow-list of endpoints sets it today —
	// notably the organization-domain verify path, which surfaces four
	// stable kinds: "verifier_unavailable", "lookup_failed",
	// "record_not_found", "mismatch". omitempty preserves the byte-
	// identical wire shape on every other endpoint.
	ErrorKind string `json:"error_kind,omitempty" example:"record_not_found"`
}

// SuccessResponse represents a standard API success with a message
type SuccessResponse struct {
	Message string `json:"message" example:"Operation successful"`
	Success bool   `json:"success" example:"true"`
}

// LoginRequest represents a user login attempt with email and password
type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	OrgSlug    string `json:"org_slug,omitempty"` // For explicit organization selection
	RememberMe bool   `json:"remember_me,omitempty"`
}

// ChangePasswordRequest represents a request to change the current user's password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

// EmergencyLoginRequest represents a break-glass login attempt
type EmergencyLoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"` // TOTP Code is mandatory for emergency access
}

// EmergencyRevokeSessionRequest is the body for POST /system/sessions/:id/emergency-revoke.
// Justification is mandatory — it is recorded verbatim in the audit trail.
type EmergencyRevokeSessionRequest struct {
	Justification string `json:"justification"`
}

// RefreshTokenRequest represents a request to refresh an access token using a refresh token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RevokeTokenRequest represents a request to revoke a refresh token
type RevokeTokenRequest struct {
	RefreshToken string    `json:"refresh_token,omitempty"` // Optional: specific token to revoke
	UserEmail    string    `json:"user_email,omitempty"`    // Optional: revoke all tokens for user (admin only)
	UserID       uuid.UUID `json:"user_id,omitempty"`       // Optional: revoke all tokens for user ID (admin only)
	SessionID    uuid.UUID `json:"session_id,omitempty"`    // Optional: revoke specific session (admin only)
}

// RevokeTokenResponse represents the response to a token revocation request
type RevokeTokenResponse struct {
	Message         string `json:"message"`
	TokensRevoked   int    `json:"tokens_revoked,omitempty"`
	SessionsRevoked int    `json:"sessions_revoked,omitempty"`
	Success         bool   `json:"success"`
}

// LoginResponse represents the response to a successful login attempt
type LoginResponse struct {
	Tokens      *TokenResponse `json:"tokens,omitempty"`
	Message     string         `json:"message"`
	SessionID   string         `json:"session_id,omitempty"`
	Email       string         `json:"email,omitempty"`
	Role        UserRole       `json:"role,omitempty"`
	Domain      string         `json:"domain,omitempty"`
	RedirectURI string         `json:"redirect_uri,omitempty"`
	Success     bool           `json:"success"`
	MFARequired bool           `json:"mfa_required,omitempty"`
	// MFAEnrollmentRequired distinguishes "the user has an existing TOTP
	// secret and must enter a code" (MFARequired only) from "the user has
	// no TOTP secret yet and must enroll" (MFARequired + this flag). The
	// UI's login flow reads this field to route the pending session to
	// the MFA-enrollment form rather than the verification form — without
	// it, an admin whose row has MFAEnabled=false sits on the
	// verification form with nothing to enter. Populated by the login
	// handler when the service-layer MFAWarning is "mfa_setup_required".
	MFAEnrollmentRequired bool `json:"mfa_enrollment_required,omitempty"`
}

// RefreshTokenResponse represents the response to a successful token refresh
type RefreshTokenResponse struct {
	Tokens  *TokenResponse `json:"tokens,omitempty"`
	Message string         `json:"message"`
	Success bool           `json:"success"`
}

// TokenResponse contains the JWT tokens and their expiration information
type TokenResponse struct {
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	IDToken          string    `json:"id_token,omitempty"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int       `json:"expires_in"`
}

// IntrospectResponse represents the response to a token introspection request (RFC 7662).
//
// 4.4g.4a re-narrowing: agentic-introspection fields and the corresponding
// actor wire-format type were removed. Agentic-token introspection lives in
// identuum-ag.
type IntrospectResponse struct {
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Active    bool     `json:"active"`
}

// ValidateSessionResponse represents the response to a session validation request
// Contains user, organization, and token information for the validated session
type ValidateSessionResponse struct {
	Organization OrganizationInfo `json:"organization"`
	User         UserInfo         `json:"user"`
	TokenInfo    TokenInfo        `json:"token_info"`
	Message      string           `json:"message"`
	Success      bool             `json:"success"`
}

// TokenInfo represents JWT token information exposed via API
type TokenInfo struct {
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Email     string    `json:"email"`
	Role      UserRole  `json:"role"`
	Domain    string    `json:"domain"`
}
