package domain

import (
	"time"

	"github.com/google/uuid"
)

// BrowserSessionToken is one row in the browser_session_tokens
// indirection table.
type BrowserSessionToken struct {
	ID             uuid.UUID
	SessionID      uuid.UUID
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	TokenHash      string // SHA-256 hex digest of the wire token.
	UserAgent      string
	IPAddress      string
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUsedAt     *time.Time
}

// IsActive reports whether the token row is currently live
// (not revoked AND not expired).
func (t *BrowserSessionToken) IsActive(now time.Time) bool {
	if t == nil {
		return false
	}
	if t.RevokedAt != nil {
		return false
	}
	return !t.ExpiresAt.Before(now)
}
