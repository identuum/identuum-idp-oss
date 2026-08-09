package types

import (
	"time"

	"github.com/google/uuid"
)

// UserAccessSummary represents aggregated access data for a user
type UserAccessSummary struct {
	LastLoginAt        *time.Time `json:"last_login_at"`
	Email              string     `json:"email"`
	OrganizationName   string     `json:"organization_name,omitempty"`
	RiskScore          string     `json:"risk_score"`
	TotalLogins        int        `json:"total_logins"`
	FailedAttempts     int        `json:"failed_attempts"`
	UniqueIPAddresses  int        `json:"unique_ip_addresses"`
	DaysSinceLastLogin int        `json:"days_since_last_login"`
	UserID             uuid.UUID  `json:"user_id"`
	OrganizationID     uuid.UUID  `json:"organization_id"`
}

// UserAccessReportRequest represents query parameters for access report
type UserAccessReportRequest struct {
	OrganizationID *uuid.UUID `json:"organization_id,omitempty" form:"organization_id"`
	StartDate      *time.Time `json:"start_date,omitempty" form:"start_date"`
	EndDate        *time.Time `json:"end_date,omitempty" form:"end_date"`
	MinDaysSince   *int       `json:"min_days_since,omitempty" form:"min_days_since"` // Filter dormant users
	Limit          int        `json:"limit,omitempty" form:"limit"`
	Offset         int        `json:"offset,omitempty" form:"offset"`
}

// UserAccessReportResponse is the API response
type UserAccessReportResponse struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Message     string               `json:"message,omitempty"`
	Summary     []*UserAccessSummary `json:"summary,omitempty"`
	TotalUsers  int                  `json:"total_users"`
	Page        int                  `json:"page,omitempty"`
	PageSize    int                  `json:"page_size,omitempty"`
	Success     bool                 `json:"success"`
}

// FailedAuthAttempt represents a single failed login attempt
type FailedAuthAttempt struct {
	AttemptedAt    time.Time  `json:"attempted_at"`
	Email          string     `json:"email"`
	IPAddress      string     `json:"ip_address"`
	UserAgent      *string    `json:"user_agent,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	Reason         string     `json:"reason,omitempty"` // From metadata
}

// FailedAuthReportRequest represents query parameters
type FailedAuthReportRequest struct {
	OrganizationID *uuid.UUID `json:"organization_id,omitempty" form:"organization_id"`
	Email          *string    `json:"email,omitempty" form:"email"`
	IPAddress      *string    `json:"ip_address,omitempty" form:"ip_address"`
	StartDate      *time.Time `json:"start_date,omitempty" form:"start_date"`
	EndDate        *time.Time `json:"end_date,omitempty" form:"end_date"`
	Limit          int        `json:"limit,omitempty" form:"limit"`
	Offset         int        `json:"offset,omitempty" form:"offset"`
}

// FailedAuthReportResponse is the API response
type FailedAuthReportResponse struct {
	GeneratedAt   time.Time            `json:"generated_at"`
	Message       string               `json:"message,omitempty"`
	Attempts      []*FailedAuthAttempt `json:"attempts,omitempty"`
	TotalAttempts int                  `json:"total_attempts"`
	Page          int                  `json:"page,omitempty"`
	PageSize      int                  `json:"page_size,omitempty"`
	Success       bool                 `json:"success"`
}

// PrivilegeChange represents a role or permission change
type PrivilegeChange struct {
	ChangedAt      time.Time  `json:"changed_at"`
	ActorID        *uuid.UUID `json:"actor_id,omitempty"`
	ActorEmail     *string    `json:"actor_email,omitempty"`
	OldRole        *string    `json:"old_role,omitempty"`
	NewRole        *string    `json:"new_role,omitempty"`
	Reason         *string    `json:"reason,omitempty"`
	SubjectEmail   string     `json:"subject_email"`
	SubjectUserID  uuid.UUID  `json:"subject_user_id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
}

// PrivilegeChangeReportRequest represents query parameters
type PrivilegeChangeReportRequest struct {
	OrganizationID *uuid.UUID `json:"organization_id,omitempty" form:"organization_id"`
	SubjectUserID  *uuid.UUID `json:"subject_user_id,omitempty" form:"subject_user_id"`
	StartDate      *time.Time `json:"start_date,omitempty" form:"start_date"`
	EndDate        *time.Time `json:"end_date,omitempty" form:"end_date"`
	Limit          int        `json:"limit,omitempty" form:"limit"`
	Offset         int        `json:"offset,omitempty" form:"offset"`
}

// PrivilegeChangeReportResponse is the API response
type PrivilegeChangeReportResponse struct {
	GeneratedAt  time.Time          `json:"generated_at"`
	Message      string             `json:"message,omitempty"`
	Changes      []*PrivilegeChange `json:"changes,omitempty"`
	TotalChanges int                `json:"total_changes"`
	Page         int                `json:"page,omitempty"`
	PageSize     int                `json:"page_size,omitempty"`
	Success      bool               `json:"success"`
}
