package domain

import (
	"time"

	"github.com/google/uuid"
)

// DCRClientRegistrationToken is the RFC 7592 §2 registration
// access token (RAT) bound to a single OAuth client. The raw
// token is returned to the registering RP exactly once in the
// DCR response and authenticates subsequent calls to the
// /api/v1/oauth/register/:client_id management surface.
//
// Storage shape: the raw token bytes are NEVER persisted. Only
// a SHA-256 hash (TokenHash) is kept; the raw token is generated
// by `crypto.GenerateRandomString(32)` (256 random bits, 64 hex
// chars) and hashed via `crypto.HashSecret` before storage.
//
// The presence of a RAT row for a given ClientID is the
// authoritative marker that the client was created via DCR
// (RFC 7591 §3) and is therefore manageable via RFC 7592 §2.
// Site-admin-created clients (via POST /api/v1/clients) carry
// no RAT row and are NOT exposed through the RFC 7592 surface.
type DCRClientRegistrationToken struct {
	ClientID  uuid.UUID
	TokenHash string
	CreatedAt time.Time
	UpdatedAt time.Time
}
