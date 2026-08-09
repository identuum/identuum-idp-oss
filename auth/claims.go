package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// privateJWTClaims is the internal JSON-tagged struct for serializing/deserializing tokens.
//
// 4.4g.4a re-narrowing: agentic-claim fields and the corresponding wire-format
// helper types and converters were removed. AG token issuance and agentic-claim
// validation live in identuum-ag.
type privateJWTClaims struct {
	UserID         uuid.UUID `json:"user_id"`
	Email          string    `json:"email"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Role           string    `json:"role"`
	SessionID      uuid.UUID `json:"session_id"`
	Type           string    `json:"type,omitempty"`
	Kind           string    `json:"kind,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	ClientID       string    `json:"client_id,omitempty"`
	// Purpose narrows the session to a specific endpoint family per
	// §F / §13.7. Empty (omitempty-suppressed) means a standard session.
	// Currently only "consent" is defined — see domain.SessionPurposeConsent.
	Purpose string `json:"purpose,omitempty"`
	// Acr is the Authentication Context Class Reference rung achieved by
	// the session that minted this token. URN string from the ladder
	// declared in auth/acr.go. Omitted on tokens minted from paths with
	// no session context (M2M client_credentials).
	Acr string `json:"acr,omitempty"`
	// AuthTime is the epoch-second timestamp of the authentication event
	// that produced the current effective ACR. Omitted when zero.
	AuthTime int64 `json:"auth_time,omitempty"`
	// Act is RFC 8693 §4.1's actor claim. Populated by token-exchange
	// issuance with the requesting client's identity (Phase 5.2.c).
	// Omitted when nil.
	Act *domain.ActClaim `json:"act,omitempty"`
	jwt.RegisteredClaims
}

// privateOIDCIDTokenClaims is the internal JSON-tagged struct for OIDC tokens
type privateOIDCIDTokenClaims struct {
	AuthTime  int64     `json:"auth_time,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	Email     string    `json:"email,omitempty"`
	Groups    []string  `json:"groups,omitempty"`
	Name      string    `json:"name,omitempty"`
	Role      string    `json:"role,omitempty"`
	SessionID uuid.UUID `json:"session_id,omitempty"`
	Acr       string    `json:"acr,omitempty"`
	Amr       []string  `json:"amr,omitempty"`
	jwt.RegisteredClaims
}
