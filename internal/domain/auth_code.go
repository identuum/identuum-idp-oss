package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuthCode represents an OIDC Authorization Code
type AuthCode struct {
	ExpiresAt           time.Time
	CreatedAt           time.Time
	SessionID           *uuid.UUID
	Code                string
	ClientID            string
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Audience            string
	UserID              uuid.UUID
}
