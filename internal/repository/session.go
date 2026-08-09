package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// SessionRepository defines the interface for session data access
type SessionRepository interface {
	// Create creates a new session with automatic session limit enforcement
	// If user has reached max sessions, automatically revokes oldest session
	Create(ctx context.Context, session *domain.Session) (*domain.Session, error)

	// GetByID retrieves a session by ID
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)

	// GetByTokenSelector retrieves a session by token selector (UUID part)
	GetByTokenSelector(ctx context.Context, selector uuid.UUID) (*domain.Session, error)

	// Update updates a session (typically for last_used_at)
	Update(ctx context.Context, session *domain.Session, orgID uuid.UUID) error

	// RotateToken atomically rotates a session's refresh-token validator hash
	// and persists the extended expiry in ONE compare-and-set statement (P0-12).
	// It updates the row ONLY while the stored token_validator_hash still equals
	// expectedValidatorHash AND the session is active (is_valid, not revoked, not
	// expired). A concurrent rotation that already advanced the hash makes the
	// WHERE match zero rows → won=false (a BENIGN CAS loss — NOT reuse/theft).
	// Returns the rotated session on success; (nil, false, nil) on a lost CAS.
	RotateToken(ctx context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error)

	// RecordACRUplift atomically writes the step-up tracking columns
	// (last_acr_uplift_at, last_acr_uplift_value) on a session in
	// response to a successful ACR step-up event. The original
	// sessions.acr is preserved — see domain.Session.EffectiveACR for
	// the resolution rule.
	RecordACRUplift(ctx context.Context, sessionID uuid.UUID, upliftAt time.Time, upliftValue string) error

	// Revoke marks a session as revoked with a reason
	Revoke(ctx context.Context, id uuid.UUID, orgID uuid.UUID, reason string) error

	// RevokeByUserID revokes all sessions for a user (e.g., on password change)
	RevokeByUserID(ctx context.Context, userID uuid.UUID, reason string) error

	// RevokeByOrganizationID revokes all sessions for an organization (e.g., org deletion)
	RevokeByOrganizationID(ctx context.Context, orgID uuid.UUID, reason string) error

	// Delete hard-deletes a session
	Delete(ctx context.Context, id uuid.UUID, orgID uuid.UUID) error

	// ListByUserID retrieves all sessions for a user
	ListByUserID(ctx context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error)

	// ListActiveByUserID retrieves only valid, non-expired sessions for a user
	ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)

	// CountActiveByUserID counts active sessions for a user
	CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error)

	// DeleteExpiredReturning removes expired sessions and returns them (for auditing)
	DeleteExpiredReturning(ctx context.Context, retentionPeriod time.Duration, batchSize int) ([]*domain.Session, error)

	// GetSessionWithUserAndOrgStatus retrieves session with user and organization active status
	// Optimized single-query method for middleware authentication validation
	GetSessionWithUserAndOrgStatus(ctx context.Context, sessionID uuid.UUID) (*domain.SessionValidationInfo, error)

	// GetStats retrieves session statistics (total, active, expired, revoked)
	GetStats(ctx context.Context) (map[string]int, error)
}

// AdminSessionRepository extends SessionRepository with admin operations
type AdminSessionRepository interface {
	SessionRepository

	// ListAll retrieves all sessions with filtering (admin only)
	ListAll(ctx context.Context, filter SessionFilter, pagination Pagination) ([]*domain.Session, int, error)

	// ListByOrganizationID retrieves all sessions for an organization (admin only)
	ListByOrganizationID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]*domain.Session, int, error)

	// GetStatsByOrganization retrieves session stats for an organization
	GetStatsByOrganization(ctx context.Context, orgID uuid.UUID) (map[string]int, error)
}

// SessionFilter represents session-specific filtering options
type SessionFilter struct {
	UserID         *uuid.UUID // Filter by user ID
	OrganizationID *uuid.UUID // Filter by organization ID
	IsValid        *bool      // Filter by valid status
	IsExpired      *bool      // Filter by expiration status
	CreatedAfter   *time.Time // Filter sessions created after this time
	CreatedBefore  *time.Time // Filter sessions created before this time
}
