package domain

import (
	"errors"
	"net/mail"
	"time"

	"github.com/google/uuid"
)

// UserRole represents the role/permission level of a user within the system
type UserRole string

const (
	RoleOrgUser   UserRole = "org_user"   // Regular organization member with basic access
	RoleOrgAdmin  UserRole = "org_admin"  // Organization administrator with user management privileges
	RoleSiteAdmin UserRole = "site_admin" // Site-wide administrator with cross-organization access
)

// AuthMethod identifies the authentication mechanism used
type AuthMethod string

const (
	AuthMethodLocal    AuthMethod = "local"
	AuthMethodLDAP     AuthMethod = "ldap"
	AuthMethodAD       AuthMethod = "ad"
	AuthMethodOIDC     AuthMethod = "oidc"
	AuthMethodMFA      AuthMethod = "mfa"
	AuthMethodWebAuthn AuthMethod = "webauthn"

	// NoPasswordSentinel is a placeholder for users without a local password (e.g. OIDC JIT).
	// It must never hash-match any input — an argon2id comparison against this literal string
	// fails because the string is not a valid PHC-formatted hash.
	NoPasswordSentinel = "oidc_managed_account_no_password" //nolint:gosec // not a credential; intentional non-secret marker
)

// AuditMetadataKey is a well-known key used in audit event metadata maps
type AuditMetadataKey = string

const (
	MetaKeyLoginMethod AuditMetadataKey = "login_method"
	MetaKeyReason      AuditMetadataKey = "reason"
)

// User.AuthSource string values. Existing rows in production carry
// "local" (native registration). Q8 introduces "id_jag" for foreign-IdP
// JIT-provisioned users (docs/ID_JAG_DESIGN.md Q8, migration 0074
// + 0079). Promoting these from hardcoded strings to named constants
// makes the audit-attribution surface (which filters on auth_source)
// less prone to typos.
const (
	AuthSourceLocal = "local"
	AuthSourceIDJag = "id_jag"
)

// IsValid checks if the role is a valid UserRole
func (r UserRole) IsValid() bool {
	switch r {
	case RoleOrgUser, RoleOrgAdmin, RoleSiteAdmin:
		return true
	}
	return false
}

// User represents a user domain model with business logic and validation
// This is the NEW pattern - pure domain model without database concerns
type User struct {
	CreatedAt                time.Time
	UpdatedAt                time.Time
	LastLoginAt              *time.Time
	DeletedAt                *time.Time // nil = not deleted; non-nil = soft-deleted timestamp
	ActivationTokenHash      *string
	VerificationTokenHash    *string
	Name                     *string
	ExternalID               *string
	OIDCIssuer               *string
	MFASecret                *string
	OrganizationName         *string
	Domain                   *string
	ActivationTokenExpiresAt *time.Time
	Role                     UserRole
	PasswordHash             string
	AuthSource               string
	Email                    string
	// ContactEmail is the address a human actually reads, kept separate from
	// the login. AdminPermissionsModel.md requires it for the site_admin,
	// whose login is pinned to site_admin@system.local: the operator who
	// installs the product types THEIR address, and it belongs here rather
	// than becoming the account's identity (G9, G15). Empty for other users.
	ContactEmail     string
	MFARecoveryCodes []string
	ID               uuid.UUID
	OrganizationID   uuid.UUID
	MFAEnabled       bool
	MFAPolicy        *string
	// OrgAuthPolicy carries the organization's auth_policy column
	// projected through the user-org JOIN (scanUserWithOrg).
	//
	// Why on User: the local-login enforcement path
	// (LocalLoginService.Login) reads the policy AFTER the user lookup
	// returns. Adding a field to User reuses the existing JOIN and
	// avoids a second org-fetch on the login hot path — same pattern
	// as MFAPolicy above.
	//
	// nil OR empty string MUST mean "permissive" (treat as
	// AuthPolicyPermissive) for backward compatibility with rows
	// loaded by callers that have not yet plumbed the column or
	// tests that build domain.User inline without setting it.
	//
	// IsLocalCredentialFlowAllowed dereferences this and applies the
	// fail-closed rule: empty/permissive → allowed; idp_only +
	// non-admin → denied; idp_only + site_admin/org_admin → allowed
	// (admin-local invariant per Decision D-004); unknown future
	// values → denied (fail-closed).
	OrgAuthPolicy *string
	// OrgMaxSessionsPerUser carries the organization's max_sessions_per_user
	// column projected through the user-org JOIN (scanUserWithOrg).
	//
	// Why on User: the session-mint hot path (LocalLoginService.Login +
	// the WebAuthn / MFA-enroll / OAuth-token callers of
	// UserSessionService.CreateUserSession) needs the cap value AFTER
	// the user lookup returns and BEFORE the new session row is
	// written. Reusing the existing JOIN avoids a second org-fetch on
	// the hot path — same pattern as OrgAuthPolicy + MFAPolicy.
	//
	// nil OR zero / negative MUST mean "unlimited" (no eviction takes
	// place) for backward compatibility with rows loaded by callers
	// that have not yet plumbed the column or tests that build
	// domain.User inline without setting it.
	//
	// Wired into UserSessionService.CreateUserSession by slice
	// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
	// (Decision D-015 §4): non-admin users whose active session count
	// would exceed the cap have their oldest sessions evicted with
	// reason "max_sessions_exceeded". site_admin and org_admin users
	// are exempt per the locked admin-local invariant (Decision D-004).
	OrgMaxSessionsPerUser *int
	// OrgPasswordComplexityEnabled carries the organization's
	// password_complexity_enabled column projected through the user-org
	// JOIN (scanUserWithOrg).
	//
	// Wired into the OSS password-write paths by slice
	// agent-a-20260715-idp-oss-password-complexity-perorg-enforcement
	// (Decision D-015 §9): PasswordResetService.ResetPassword and
	// OrganizationActivationService.ConsumeActivationToken consult
	// this projection AFTER the user lookup and BEFORE the password
	// hash write. UserService.Create + Update accept the policy via
	// their option structs from the handler layer.
	//
	// nil OR true ⇒ STRICT mode (complexity required). The safe
	// default for backward-compat with pre-projection rows + inline
	// test fixtures is the same as the production safe default —
	// complexity enabled. ONLY an explicit `false` from the
	// organizations row relaxes the policy.
	//
	// Bootstrap / recovery / setup control-plane password writes are
	// EXEMPT from per-org policy and ALWAYS use the strict-mode
	// `ValidatePassword` helper per the locked admin-local invariant
	// (Decision D-004).
	OrgPasswordComplexityEnabled *bool
	OIDCLinked                   bool
	RequiresPasswordChange       bool
	EmailVerified                bool
	Banned                       bool
}

// ValidateUserEmail is THE email grammar for a user record. Extracted from
// User.Validate by THE-UNVALIDATED-REST so the UPDATE path can enforce the
// SAME rule the create path enforces instead of writing the value raw and
// letting the users.chk_user_email_format CHECK constraint answer 500.
//
// It is deliberately not a normalizer: neither create nor update lowercases
// or trims a user email, so trimming here would make the two paths disagree.
func ValidateUserEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("email is invalid")
	}
	return nil
}

// ValidateUserRole is THE role rule. The users.role column is a Postgres
// ENUM, so an unlisted role was previously refused by the database with a
// 500 rather than by the service with a 400.
func ValidateUserRole(role UserRole) error {
	if !role.IsValid() {
		return errors.New("invalid role")
	}
	return nil
}

// Validate performs business logic validation on the User domain model.
//
// Email format check: previously absent at this layer. Now uses
// net/mail.ParseAddress, which implements RFC 5322 (lenient form,
// matching what receiving SMTP servers actually accept). Wired-in by
// `agent-claude-20260624-idp-oss-user-email-format-wirein` replacing the
// previously-unused 100-line homegrown IsValidEmail (complexity 50) in
// tools/tools.go. Spec-compliant, callable from the stdlib, ~5
// cyclomatic instead of 50.
func (u *User) Validate() error {
	if err := ValidateUserEmail(u.Email); err != nil {
		return err
	}

	// Check organization ID based on role
	if u.OrganizationID == uuid.Nil {
		// Only Site Admins allow nil OrganizationID (Infrastructure Admin)
		if u.Role != RoleSiteAdmin {
			return errors.New("organization_id is required")
		}
	}

	if err := ValidateUserRole(u.Role); err != nil {
		return err
	}

	if u.PasswordHash == "" {
		return errors.New("password_hash is required")
	}

	return nil
}

// CanLogin checks if user can authenticate (business rule)
// requireEmailVerification is injected from config/service
func (u *User) CanLogin(requireEmailVerification bool) (bool, string) {
	if u.DeletedAt != nil {
		return false, "account not found" // Don't reveal deletion
	}

	if u.Banned {
		return false, "account banned"
	}

	// If verification is required, enforce it
	if requireEmailVerification && !u.EmailVerified {
		return false, "email not verified"
	}

	return true, ""
}

// IsSiteAdmin checks if user has site-wide admin privileges
func (u *User) IsSiteAdmin() bool {
	return u.Role == RoleSiteAdmin
}

// IsOrgAdmin returns true for both RoleOrgAdmin and RoleSiteAdmin.
//
// Intended use: login-path checks where both administrative roles are treated
// equivalently, such as the idp_only policy bypass in validateLocalLogin (admin
// lockout prevention). The name "IsOrgAdmin" is retained for backward compatibility.
//
// WARNING: Do not use this method as a tenant resource-management authorization gate.
// Phase 8.d guards (guardSiteAdminTenant*) enforce the correct boundary.
// For a check that returns true ONLY for RoleOrgAdmin, use IsOrgAdminOnly().
func (u *User) IsOrgAdmin() bool {
	return u.Role == RoleOrgAdmin || u.Role == RoleSiteAdmin
}

// IsOrgAdminOnly returns true if and only if the user has exactly RoleOrgAdmin.
// Unlike IsOrgAdmin(), this returns false for RoleSiteAdmin.
// Use this helper when checking for org_admin authority in authorization gates
// where site_admin must not be granted the same access.
func (u *User) IsOrgAdminOnly() bool {
	return u.Role == RoleOrgAdmin
}

// UpdateLastLogin updates the last login timestamp.
// now must be injected by the caller (service layer).
func (u *User) UpdateLastLogin(now time.Time) {
	u.LastLoginAt = &now
}
