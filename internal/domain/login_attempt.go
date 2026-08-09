package domain

import (
	"time"

	"github.com/google/uuid"
)

// LoginAttempt is one row in the login_attempts table.
type LoginAttempt struct {
	ID        uuid.UUID
	EmailHash string
	IPHash    string
	Purpose   string
	Success   bool
	CreatedAt time.Time
	Metadata  map[string]any
}
