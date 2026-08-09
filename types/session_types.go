package types

import (
	"time"

	"github.com/google/uuid"
)

// SessionInfo represents user session information exposed via API.
// Contains only user-relevant fields for session management, excluding internal security details.
type SessionInfo struct {
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Token      string     `json:"token"`
	ID         uuid.UUID  `json:"id"`
	IsActive   bool       `json:"is_active"`
	IsCurrent  bool       `json:"is_current"`
}

// SessionCleanupStats represents the results of a session cleanup operation
type SessionCleanupStats struct {
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	Errors           []string  `json:"errors,omitempty"`
	TotalToClean     int       `json:"total_to_clean"`
	TotalCleaned     int       `json:"total_cleaned"`
	BatchesProcessed int       `json:"batches_processed"`
}
