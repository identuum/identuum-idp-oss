package domain

import (
	"time"

	"github.com/google/uuid"
)

// OAuthAuthorizationCode is the persistent record of one issued
// authorization code for the future /authorize → /token
// exchange. The raw code value NEVER lands in this struct or in
// the DB — only its SHA-256 hex digest sits in CodeHash. The
// caller-visible code is returned EXACTLY ONCE by
// AuthorizationCodeService.Create.
type OAuthAuthorizationCode struct {
	ID                  uuid.UUID
	CodeHash            string
	ClientID            string
	UserID              uuid.UUID
	OrganizationID      *uuid.UUID
	SessionID           uuid.UUID
	RedirectURI         string
	Scope               string
	Audience            string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
	Metadata            map[string]any

	// What the FIRST exchange of this code minted (THE-CODE-REUSE-REVOKER,
	// RFC 6749 §4.1.2). Written once by the token endpoint after minting;
	// read by the reuse revoker so a replayed code revokes exactly these.
	// Zero/nil = nothing recorded.
	IssuedAccessJTI       string
	IssuedAccessExpiresAt *time.Time
	IssuedRefreshTokenID  *uuid.UUID
}
