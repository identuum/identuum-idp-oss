package domain

import (
	"time"

	"github.com/google/uuid"
)

// JWTClaims represents the claims structure for access tokens. This is the
// domain-layer model.
//
// 4.4g.4b re-narrowing: agentic identity fields and the corresponding
// helper types / chain-depth helpers were removed. Agentic claim handling
// lives in identuum-ag.
type JWTClaims struct {
	ExpiresAt      time.Time
	IssuedAt       time.Time
	NotBefore      *time.Time
	ClientID       string
	Type           string
	Kind           string
	Scope          string
	Issuer         string
	Subject        string
	Role           string
	Email          string
	ID             string
	Audience       []string
	SessionID      uuid.UUID
	UserID         uuid.UUID
	OrganizationID uuid.UUID

	// Acr is the Authentication Context Class Reference of the session that
	// minted this access token. Empty for tokens minted by paths with no
	// session context (M2M client_credentials).
	Acr string

	// AuthTime is the epoch-second timestamp of the authentication event
	// that produced the current effective ACR.
	AuthTime int64

	// Purpose narrows the scope of a session beyond the subject and role.
	// Empty (the zero value) means a standard session. Currently defined:
	//   - "" (empty)               standard session, no purpose narrowing.
	//   - SessionPurposeConsent    short-lived session for the consent-UI
	//                              federation flow.
	Purpose string

	// SPIFFEID is the canonical "spiffe://<td>/<path>" identifier from the
	// (validated) JWT-SVID's `sub` claim. Populated only on access tokens
	// minted via the SPIFFE federation branch; omitted from all other
	// tokens via JSON omitempty in the wire layer. Empty on non-SPIFFE
	// tokens.
	SPIFFEID string

	// Act is the RFC 8693 §4.1 actor claim. Populated by token-exchange
	// (Phase 5.2.c) issuance with the requesting client's identity for
	// audit traceability. Nil on tokens minted by non-exchange paths;
	// JSON-omitted on the wire when nil.
	Act *ActClaim
}

// ActClaim is the JSON shape of RFC 8693 §4.1's `act` claim. v1 carries
// only client_id (the requesting OAuth client at /token); subject-chain
// delegation (the spec's nested `act.act` structure) is deferred per
// design Q-7 (impersonation-only v1).
type ActClaim struct {
	ClientID string `json:"client_id,omitempty"`
}

// Session-purpose constants. Compared against JWTClaims.Purpose to gate
// access. Stable wire values — once minted, tokens carrying these strings
// MUST continue to be interpreted with the same semantics across versions.
const (
	// SessionPurposeConsent identifies a short-lived session minted by the
	// consent-UI federation flow when an org_user has no Identuum session
	// of their own.
	SessionPurposeConsent = "consent"
)

// IsConsentPurposeSession reports whether the given claims belong to a
// short-lived consent-only session. nil claims return false.
func IsConsentPurposeSession(claims *JWTClaims) bool {
	if claims == nil {
		return false
	}
	return claims.Purpose == SessionPurposeConsent
}

// OIDCIDTokenClaims represents standard ID Token claims in the domain layer.
type OIDCIDTokenClaims struct {
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore *time.Time
	Name      string
	Role      string
	Acr       string
	Issuer    string
	Subject   string
	Email     string
	Nonce     string
	ID        string
	Amr       []string
	Audience  []string
	Groups    []string
	AuthTime  int64
	SessionID uuid.UUID
}

// TokenIntrospection represents metadata about a token in the domain.
//
// 4.4g.4b re-narrowing: agentic introspection fields removed. Agentic-token
// introspection lives in identuum-ag.
type TokenIntrospection struct {
	Scope     string
	ClientID  string
	Username  string
	TokenType string
	Sub       string
	Aud       []string
	Iss       string
	Jti       string
	Exp       int64
	Iat       int64
	Nbf       int64
	Active    bool
}
