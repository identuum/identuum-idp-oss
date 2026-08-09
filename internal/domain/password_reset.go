package domain

import (
	"time"

	"github.com/google/uuid"
)

// PasswordReset represents a password reset request domain model
type PasswordReset struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
	TokenHash string
	UserID    uuid.UUID
}

// IsExpired checks if the reset token has expired.
// now must be injected by the caller (service layer).
func (p *PasswordReset) IsExpired(now time.Time) bool {
	return now.After(p.ExpiresAt)
}

// IsValid checks if the reset token is usable (not used and not expired).
// now must be injected by the caller (service layer).
func (p *PasswordReset) IsValid(now time.Time) bool {
	return p.UsedAt == nil && !p.IsExpired(now)
}
