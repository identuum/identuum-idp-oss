package types

import (
	"time"

	"github.com/google/uuid"
)

// UserInfo represents user information exposed via API
type UserInfo struct {
	CreatedAt         time.Time  `json:"created_at"`
	OrganizationName  *string    `json:"organization_name,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	Name              *string    `json:"name,omitempty"`
	Role              UserRole   `json:"role"`
	Domain            string     `json:"domain"`
	Email             string     `json:"email"`
	OrganizationID    uuid.UUID  `json:"organization_id"`
	ID                uuid.UUID  `json:"id"`
	Active            bool       `json:"active"`
	Banned            bool       `json:"banned"`
	EmailVerified     bool       `json:"email_verified"`
	Deleted           bool       `json:"deleted"`
	MfaEnabled        bool       `json:"mfa_enabled"`
	MfaPolicy         *string    `json:"mfa_policy,omitempty"`
	InsecureMfaBypass bool       `json:"insecure_mfa_bypass,omitempty"`
}

// CreateUserRequest represents a request to create a new user account
type CreateUserRequest struct {
	Email              string   `json:"email" binding:"required"`      // User email address (must be unique)
	Name               *string  `json:"name,omitempty"`                // Optional user display name
	Password           string   `json:"password,omitempty"`            // Plain text password; omit to trigger invitation flow
	Role               UserRole `json:"role" binding:"required"`       // User role within organization
	OrganizationDomain string   `json:"organization_domain,omitempty"` // Target organization domain (site_admin only)
}

// UpdateUserRequest represents a request to update an existing user
type UpdateUserRequest struct {
	Name          *string   `json:"name,omitempty"`
	Active        *bool     `json:"active"`
	EmailVerified *bool     `json:"email_verified"`
	Email         string    `json:"email"`
	Password      string    `json:"password"`
	Role          *UserRole `json:"role,omitempty"`
}

// UserResponse represents the response for user operations
type UserResponse struct {
	User          *UserInfo `json:"user,omitempty"`
	ActivationURL *string   `json:"activation_url,omitempty"`
	Message       string    `json:"message"`
	Success       bool      `json:"success"`
}

// UserListResponse represents the response for listing users
type UserListResponse struct {
	Message    string     `json:"message"`
	Users      []UserInfo `json:"users,omitempty"`
	Count      int        `json:"count"`
	TotalCount int        `json:"total_count"`
	Offset     int        `json:"offset"`
	Limit      int        `json:"limit"`
	Success    bool       `json:"success"`
}

// ============================================================================
// Bulk User Creation Types
// ============================================================================

// BulkUserEntry is a single row in a bulk-create request.
// Role is always org_user; organization is resolved from the authenticated actor.
type BulkUserEntry struct {
	Email string `json:"email" binding:"required"`
	Name  string `json:"name"  binding:"required"`
}

// BulkCreateUsersRequest is the request body for POST /users/bulk.
// Accepts up to 50 entries.
type BulkCreateUsersRequest struct {
	Users []BulkUserEntry `json:"users" binding:"required"`
}

// BulkCreateUserResult is the per-row outcome returned in BulkCreateUsersResponse.
// Name and Email are always present to allow org admins to distribute activation
// links out-of-band (e.g. in air-gapped deployments).
type BulkCreateUserResult struct {
	ActivationURL *string `json:"activation_url,omitempty"`
	Email         string  `json:"email"`
	Name          string  `json:"name"`
	ErrorMessage  string  `json:"error_message,omitempty"`
	Success       bool    `json:"success"`
}

// BulkCreateUsersResponse is a legacy 207 Multi-Status shape retained for
// internal reference only. The live POST /users/bulk endpoint is
// SYNCHRONOUS: it returns a best-effort per-row result inline (the
// handler-local bulkCreateUsersResponse in
// internal/handlers/user_bulk_create.go). The async job pattern this shape
// once anticipated was never wired into OSS — the job queue was removed.
type BulkCreateUsersResponse struct {
	Results []BulkCreateUserResult `json:"results"`
	Message string                 `json:"message"`
	Created int                    `json:"created"`
	Failed  int                    `json:"failed"`
	Success bool                   `json:"success"`
}
