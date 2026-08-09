package types

import (
	"time"

	"github.com/google/uuid"
)

// AuditEventType represents the category of audit event
type AuditEventType string

const (
	// Authentication events
	AuditAuthSuccess    AuditEventType = "auth_success"
	AuditAuthFailure    AuditEventType = "auth_failure"
	AuditTokenIssued    AuditEventType = "token_issued"
	AuditTokenRefreshed AuditEventType = "token_refreshed"
	AuditTokenRevoked   AuditEventType = "token_revoked"
	AuditSessionCreated AuditEventType = "session_created"
	AuditSessionRevoked AuditEventType = "session_revoked"
	AuditLogout         AuditEventType = "logout"
	AuditSessionExpired AuditEventType = "session_expired"

	// User management
	AuditUserCreated                AuditEventType = "user_created"
	AuditUserUpdated                AuditEventType = "user_updated"
	AuditUserDeleted                AuditEventType = "user_deleted"
	AuditUserActivated              AuditEventType = "user_activated"
	AuditUserDeactivated            AuditEventType = "user_deactivated"
	AuditPasswordChanged            AuditEventType = "password_changed"
	AuditRoleChanged                AuditEventType = "role_changed"
	AuditUserPasswordResetRequested AuditEventType = "user_password_reset_requested"
	AuditUserPasswordResetCompleted AuditEventType = "user_password_reset_completed"

	// Organization management
	AuditOrgCreated         AuditEventType = "organization_created"
	AuditOrgUpdated         AuditEventType = "organization_updated"
	AuditOrgDeleted         AuditEventType = "organization_deleted"
	AuditOrgActivated       AuditEventType = "organization_activated"
	AuditOrgDeactivated     AuditEventType = "organization_deactivated"
	AuditMaxSessionsChanged AuditEventType = "max_sessions_changed"

	// Key management (CRITICAL for SOC2)
	AuditKeyGenerated  AuditEventType = "signing_key_generated"
	AuditKeyRotated    AuditEventType = "signing_key_rotated"
	AuditKeyDeprecated AuditEventType = "signing_key_deprecated"
	AuditKeyDeleted    AuditEventType = "signing_key_deleted"
	AuditKeyReloaded   AuditEventType = "signing_key_reloaded"

	// M2M / Service Accounts
	AuditSACreated     AuditEventType = "service_account_created"
	AuditSADeleted     AuditEventType = "service_account_deleted"
	AuditAPIKeyCreated AuditEventType = "api_key_created"
	AuditAPIKeyRevoked AuditEventType = "api_key_revoked"

	// OAuth2 Client Management
	AuditClientCreated AuditEventType = "client_created"
	AuditClientUpdated AuditEventType = "client_updated"
	AuditClientDeleted AuditEventType = "client_deleted" // If implemented

	// Security events
	AuditRateLimitExceeded AuditEventType = "rate_limit_exceeded"
	AuditConcurrentSession AuditEventType = "concurrent_session_limit"
	AuditPolicyChanged     AuditEventType = "policy_changed"
	AuditAccessDenied      AuditEventType = "access_denied"
	AuditPermissionDenied  AuditEventType = "permission_denied" // Distinct from AccessDenied for specific scanning detection
	AuditResourceNotFound  AuditEventType = "resource_not_found"
	AuditSecurityViolation AuditEventType = "security_violation"
	AuditAnomalyDetected   AuditEventType = "anomaly_detected"

	// System events
	AuditSystemBackupCompleted AuditEventType = "system_backup_completed"
	AuditSystemBackupFailed    AuditEventType = "system_backup_failed"
	AuditStepUpTriggered       AuditEventType = "step_up_triggered"
	AuditStepUpPassed          AuditEventType = "step_up_passed"
	AuditSessionRevokedAnomaly AuditEventType = "session_revoked_anomaly"

	// Directory Sync
	AuditDirectorySyncCompleted AuditEventType = "directory_sync_completed"
	AuditDirectorySyncFailed    AuditEventType = "directory_sync_failed"

	// Identity Provider Management
	AuditIDPCreated AuditEventType = "identity_provider_created"
	AuditIDPUpdated AuditEventType = "identity_provider_updated"
	AuditIDPDeleted AuditEventType = "identity_provider_deleted"

	// Webhook Management
	AuditWebhookEndpointCreated AuditEventType = "webhook_endpoint_created"
	AuditWebhookEndpointDeleted AuditEventType = "webhook_endpoint_deleted"
)

// AuditEventPriority defines the importance of the event
type AuditEventPriority string

const (
	AuditPriorityCritical AuditEventPriority = "critical" // Must never be dropped
	AuditPriorityHigh     AuditEventPriority = "high"     // Should strictly avoid dropping
	AuditPriorityNormal   AuditEventPriority = "normal"   // Can be dropped if queue full
)

// AuditEvent represents a single audit trail entry
type AuditEvent struct {
	CreatedAt           time.Time          `json:"created_at" db:"created_at"`
	SubjectType         *string            `json:"subject_type,omitempty" db:"subject_type"`
	IPAddress           *string            `json:"ip_address,omitempty" db:"ip_address"`
	Metadata            map[string]any     `json:"metadata,omitempty" db:"metadata"`
	ActorID             *uuid.UUID         `json:"actor_id,omitempty" db:"actor_id"`
	ActorEmail          *string            `json:"actor_email,omitempty" db:"actor_email"`
	ActorRole           *UserRole          `json:"actor_role,omitempty" db:"actor_role"`
	RequestID           *string            `json:"request_id,omitempty" db:"request_id"`
	SubjectID           *uuid.UUID         `json:"subject_id,omitempty" db:"subject_id"`
	ActorOrganizationID *uuid.UUID         `json:"actor_organization_id,omitempty" db:"actor_organization_id"`
	SubjectEmail        *string            `json:"subject_email,omitempty" db:"subject_email"`
	UserAgent           *string            `json:"user_agent,omitempty" db:"user_agent"`
	CorrelationID       *string            `json:"correlation_id,omitempty" db:"correlation_id"`
	Priority            AuditEventPriority `json:"priority" db:"priority"`
	ActorType           string             `json:"actor_type" db:"actor_type"`
	EventType           AuditEventType     `json:"event_type" db:"event_type"`
	ID                  uuid.UUID          `json:"id" db:"id"`
}

// AuditFilters defines query filters for audit event retrieval
type AuditFilters struct {
	ActorID     *uuid.UUID      `json:"actor_id,omitempty"`
	ActorOrgID  *uuid.UUID      `json:"actor_organization_id,omitempty"`
	SubjectType *string         `json:"subject_type,omitempty"`
	SubjectID   *uuid.UUID      `json:"subject_id,omitempty"`
	EventType   *AuditEventType `json:"event_type,omitempty"`
	IPAddress   *string         `json:"ip_address,omitempty"`
	StartDate   *time.Time      `json:"start_date,omitempty"`
	EndDate     *time.Time      `json:"end_date,omitempty"`
	SortColumn  string          `json:"sort_column,omitempty"`
	SortOrder   string          `json:"sort_order,omitempty"`
	Limit       int             `json:"limit,omitempty"`
	Offset      int             `json:"offset,omitempty"`
}

// AuditResponse is the API response for audit event queries
type AuditResponse struct {
	Message    string        `json:"message,omitempty"`
	Events     []*AuditEvent `json:"events,omitempty"`
	TotalCount int           `json:"total_count,omitempty"`
	Page       int           `json:"page,omitempty"`
	PageSize   int           `json:"page_size,omitempty"`
	Success    bool          `json:"success"`
}
