package types

import (
	"time"

	"github.com/google/uuid"
)

// OrganizationInfo represents organization information exposed via API (without sensitive fields)
type OrganizationInfo struct {
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
	Name                        string    `json:"name"`
	OrgSlug                     string    `json:"org_slug"`
	Domain                      string    `json:"domain"`
	MFAPolicy                   string    `json:"mfa_policy"`
	AuthPolicy                  string    `json:"auth_policy"`
	M2MAnomalyLimit             int       `json:"m2m_anomaly_limit"`
	M2MAnomalyWindowSeconds     int       `json:"m2m_anomaly_window_seconds"`
	ServiceAccountExpiryDays    int       `json:"service_account_expiry_days"`
	ID                          uuid.UUID `json:"id" db:"id"`
	AllowPublicRegistration     bool      `json:"allow_public_registration"`
	RequireRegistrationApproval bool      `json:"require_registration_approval"`
	Deleted                     bool      `json:"deleted"`
	RequireStrictReauth         bool      `json:"require_strict_reauth"`
	LocalAdminOnly              bool      `json:"local_admin_only"`
	PasswordComplexityEnabled   bool      `json:"password_complexity_enabled"`
	IsClaimed                   bool      `json:"is_claimed"`
	// CanAssignAdmin is true when IsClaimed=true but all org_admin users are
	// unverified (expired-pending-invitation state). Signals that site_admin
	// recovery delegation is available via the assign-admin flow.
	CanAssignAdmin bool `json:"can_assign_admin"`
	Active         bool `json:"active"`
	// External-IdP / SCIM observability fields. Surfaced on the
	// org-admin pages (Phase F.5 + Phase G/I).
	DefaultConsentIDPID *uuid.UUID `json:"default_consent_idp_id,omitempty"`
	LastSCIMSyncAt      *time.Time `json:"last_scim_sync_at,omitempty"`
}

// OrganizationWithUsers represents organization information with associated users
type OrganizationWithUsers struct {
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
	Name                        string     `json:"name"`
	Domain                      string     `json:"domain"`
	MFAPolicy                   string     `json:"mfa_policy"`
	AuthPolicy                  string     `json:"auth_policy"`
	Users                       []UserInfo `json:"users"`
	M2MAnomalyWindowSeconds     int        `json:"m2m_anomaly_window_seconds"`
	ServiceAccountExpiryDays    int        `json:"service_account_expiry_days"`
	M2MAnomalyLimit             int        `json:"m2m_anomaly_limit"`
	ID                          uuid.UUID  `json:"id" db:"id"`
	Deleted                     bool       `json:"deleted"`
	RequireStrictReauth         bool       `json:"require_strict_reauth"`
	LocalAdminOnly              bool       `json:"local_admin_only"`
	PasswordComplexityEnabled   bool       `json:"password_complexity_enabled"`
	IsClaimed                   bool       `json:"is_claimed"`
	AllowPublicRegistration     bool       `json:"allow_public_registration"`
	RequireRegistrationApproval bool       `json:"require_registration_approval"`
	Active                      bool       `json:"active"`
}

// CreateOrganizationRequest represents a request to create a new organization
type CreateOrganizationRequest struct {
	Name                        string `json:"name" binding:"required"`
	Domain                      string `json:"domain,omitempty"`
	Active                      *bool  `json:"active,omitempty"`
	AuthPolicy                  string `json:"auth_policy,omitempty"`
	MfaPolicy                   string `json:"mfa_policy,omitempty"`
	ServiceAccountExpiryDays    *int   `json:"service_account_expiry_days,omitempty"`
	AllowPublicRegistration     *bool  `json:"allow_public_registration,omitempty"`
	RequireRegistrationApproval *bool  `json:"require_registration_approval,omitempty"`
	RequireStrictReauth         *bool  `json:"require_strict_reauth,omitempty"`
	Slug                        string `json:"slug,omitempty" validate:"omitempty" binding:"omitempty"`
	AdminEmail                  string `json:"admin_email,omitempty"`
}

// UpdateOrganizationRequest represents a request to update an existing organization
type UpdateOrganizationRequest struct {
	AuthPolicy                  *string `json:"auth_policy,omitempty"`
	Active                      *bool   `json:"active,omitempty"`
	MaxSessionsPerUser          *int    `json:"max_sessions_per_user,omitempty"`
	MFAPolicy                   *string `json:"mfa_policy,omitempty"`
	AllowPublicRegistration     *bool   `json:"allow_public_registration,omitempty"`
	RequireRegistrationApproval *bool   `json:"require_registration_approval,omitempty"`
	ServiceAccountExpiryDays    *int    `json:"service_account_expiry_days,omitempty"`
	M2MAnomalyLimit             *int    `json:"m2m_anomaly_limit,omitempty"`
	M2MAnomalyWindowSeconds     *int    `json:"m2m_anomaly_window_seconds,omitempty"`
	RequireStrictReauth         *bool   `json:"require_strict_reauth,omitempty"`
	LocalAdminOnly              *bool   `json:"local_admin_only,omitempty"`
	PasswordComplexityEnabled   *bool   `json:"password_complexity_enabled,omitempty"`
	Domain                      string  `json:"domain"`
	Name                        string  `json:"name"`
}

// OrganizationResponse represents the response for organization operations
type OrganizationResponse struct {
	Organization    *OrganizationInfo `json:"organization,omitempty"`
	Message         string            `json:"message"`
	ActivationToken string            `json:"activation_token,omitempty"`
	Success         bool              `json:"success"`
}

// OrganizationListResponse represents the response for listing organizations
type OrganizationListResponse struct {
	Message       string             `json:"message"`
	Organizations []OrganizationInfo `json:"organizations,omitempty"`
	Count         int                `json:"count"`
	TotalCount    int                `json:"total_count"`
	Offset        int                `json:"offset"`
	Limit         int                `json:"limit"`
	Success       bool               `json:"success"`
}
