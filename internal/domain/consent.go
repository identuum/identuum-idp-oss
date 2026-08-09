package domain

import (
	"time"

	"github.com/google/uuid"
)

// Consent represents a user's approved consent for an OAuth2 client
type Consent struct {
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Scope         string
	ID            uuid.UUID
	UserID        uuid.UUID
	ClientID      uuid.UUID
	APIResourceID *uuid.UUID
}
