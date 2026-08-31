package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Tier int

const (
	TierBase Tier = iota
	TierPro
	TierEnterprise
)

func (t Tier) String() string {
	switch t {
	case TierPro:
		return "TierPro"
	case TierEnterprise:
		return "TierEnterprise"
	default:
		return "TierBase"
	}
}

func ParseTier(s string) Tier {
	switch s {
	case "TierPro":
		return TierPro
	case "TierEnterprise":
		return TierEnterprise
	default:
		return TierBase
	}
}

type Feature string

const (
	FeatureWebhooks Feature = "webhooks"
	FeatureAuditLog Feature = "audit_log"
)

// Organization represents an organization domain model.
//
// 4.4g.4a re-narrowing: AG fields and AG-related validators / constants
// removed (agent issuance toggles, ID-JAG issuance/consumption flags, CBAA
// poll gating, reviewer-side ACR floor, agent chain depth override,
// per-org input/session token budgets, ITDR per-org thresholds, ITDR
// privacy modes, fail-closed gate, consent-federation default issuer
// pointer). AG-side org-settings logic lives in identuum-ag.
//
// POLICY FIELD ENFORCEMENT STATUS IN OSS (audited 2026-06-24).
//
// Of the 12 operator-settable policy fields on this struct, 2 are
// enforced at runtime in OSS:
//
//   - MFAPolicy — enforced via IsMFARequiredForUser →
//     LocalLoginService.Login + MFAEnrollmentService.DisableSelfWithProof.
//   - AuthPolicy — enforced 2026-06-24 via domain.IsLocalCredentialFlowAllowed
//     wired into LocalLoginService.Login (slices
//     agent-a-20260709-idp-oss-authpolicy-local-login-enforcement +
//     agent-a-20260710-idp-oss-authpolicy-e2e-projection-pin). Site_admin
//     and org_admin retain local credential access regardless of
//     auth_policy per the locked admin-local invariant (Decision D-004).
//     The `metrics.AuthPolicyViolation` counter is wired to its first
//     production .Inc() at the policy-denied call site.
//
// The remaining 10 fields below have a per-field disposition decided
// 2026-06-24 — see wiki/platform/org-policy-enforcement-decision.md
// (Decision D-015) for the full matrix:
//
//	OSS_ENFORCE       (follow-on slice planned):
//	  - MaxSessionsPerUser
//	  - AllowPublicRegistration
//	  - RequireRegistrationApproval
//	  - PasswordComplexityEnabled
//
//	CE_ENFORCE        (enforcement point lives in CE; OSS has no
//	                   surface to gate the value today):
//	  - RequireStrictReauth          (CE OIDC RP authorize / max_age)
//	  - LocalAdminOnly               (CE OIDC RP block-admins;
//	                                  operationally redundant in OSS
//	                                  because Decision D-004 already
//	                                  forces admins to local credentials)
//
//	FUTURE_DEFERRED   (substantial subsystem required, not settable
//	                   via OSS API today, not a security hole):
//	  - M2MAnomalyLimit
//	  - M2MAnomalyWindowSeconds
//	  - ServiceAccountExpiryDays
//
//	NEEDS_OWNER_DECISION (semantics undefined):
//	  - ApiAuthorizationPolicy
//
// Operators reading per-field doc-comments below should consult the
// decision page for the rationale, planned enforcement slice (if any),
// and CE-handoff notes (if any). Until the corresponding follow-on
// slice ships, fields tagged OSS_ENFORCE still do nothing at the
// runtime layer — the field comments below document that posture
// honestly per the Path-C documentation pass from the 2026-06-24
// audit-action pass.
type Organization struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
	// MFAPolicy is WIRED. "required" forces TOTP enrollment + verification
	// at login via IsMFARequiredForUser → LocalLoginService.Login.
	MFAPolicy string
	Name      string
	Domain    string
	OrgSlug   string
	// AuthPolicy: WIRED in OSS as of 2026-06-24 (slices
	// agent-a-20260709-idp-oss-authpolicy-local-login-enforcement +
	// agent-a-20260710-idp-oss-authpolicy-e2e-projection-pin).
	// Enforced via domain.IsLocalCredentialFlowAllowed → LocalLoginService.
	// Login. "idp_only" denies non-admin local password login with the
	// generic ErrLoginInvalidCredentials (enumeration-safe); site_admin
	// and org_admin retain access per Decision D-004. The remaining
	// gap — true federated routing for "mixed" orgs — is tracked as a
	// CE_ENFORCE follow-on per Decision D-015 (see
	// wiki/platform/org-policy-enforcement-decision.md).
	AuthPolicy string
	// ApiAuthorizationPolicy: UNWIRED in OSS. The constants
	// APIAuthPolicyStrict / APIAuthPolicyImplicit are defined and used
	// as Create defaults, but no service/middleware differentiates the
	// two values at the API-authorization gate.
	ApiAuthorizationPolicy string
	// M2MAnomalyWindowSeconds: UNWIRED in OSS AND not settable via the
	// public API. No rate limiter reads this field. Inert state until
	// an enforcement slice ships.
	M2MAnomalyWindowSeconds int
	// MaxSessionsPerUser: UNWIRED in OSS. The value is validated (1-100)
	// and stored, but no session-creation path enforces the limit; users
	// can hold arbitrarily many concurrent sessions regardless of the
	// configured cap.
	MaxSessionsPerUser int
	// ServiceAccountExpiryDays: UNWIRED in OSS AND not settable via the
	// public API. No reaper job consumes this value; service accounts
	// do not auto-expire. Inert state.
	ServiceAccountExpiryDays int
	// M2MAnomalyLimit: UNWIRED in OSS AND not settable via the public
	// API. No rate limiter reads this field. Inert state.
	M2MAnomalyLimit int
	Tier            Tier
	ID              uuid.UUID
	// AllowPublicRegistration: ENFORCED_BY_ABSENCE in OSS (Decision D-015
	// disposition updated 2026-06-24 by slice
	// agent-a-20260712-idp-oss-allowpublicregistration-enforcement after
	// verification of the OSS handler inventory).
	//
	// Posture: OSS Starter does NOT mount a public/self-registration
	// route. User creation is admin-gated only:
	//   - POST /api/v1/users requires site_admin OR (org_admin +
	//     users:create scope) — see internal/handlers/users.go.
	//   - The claim flow (POST /api/v1/auth/claim) consumes an
	//     admin-minted invitation token and creates exactly one
	//     org_admin; not a public-registration surface.
	//   - The organization-activation flow (POST /api/v1/auth/
	//     organizations/activate) consumes an admin-minted activation
	//     token and creates the first org_admin; not a
	//     public-registration surface.
	//   - UserService.Create is documented as admin-gated at the HTTP
	//     middleware layer and explicitly out-of-scope for
	//     "registration-approval flows" per its own doc-comment.
	//
	// Because no public-registration handler exists, setting
	// AllowPublicRegistration=false matches the actual runtime
	// behavior (no public registration occurs regardless of the field
	// value) and setting it to true does NOT enable any new surface —
	// the field is operationally inert in OSS.
	//
	// Why the field is kept in admin DTOs anyway: forward-compat with
	// CE composition. CE may later add a public-registration handler
	// (per Decision D-015 the OSS_ENFORCE follow-on slice was
	// reclassified to ENFORCED_BY_ABSENCE in OSS / DEFERRED_FOR_CE for
	// the surface itself). When that handler ships, it MUST consult
	// this field before any user row is written.
	//
	// Distinct from features.PublicRegistration which is a license-tier
	// feature gate (currently enabled at OSS Starter but with no
	// production consumer in OSS today — the same gap).
	AllowPublicRegistration bool
	// RequireRegistrationApproval: UNWIRED in OSS. The PATCH handler
	// accepts the field but no signup/approval flow reads it. New users
	// are not held for admin approval regardless of the configured
	// value.
	RequireRegistrationApproval bool
	// RequireStrictReauth: UNWIRED in OSS AND not settable via the
	// public API. No reauth-check call site reads this field; sensitive
	// operations do not require fresh authentication regardless of the
	// configured value.
	RequireStrictReauth bool

	// LocalAdminOnly: UNWIRED in OSS AND not settable via the public
	// API. No code path reads this field; admin role assignment is not
	// restricted to local-credential users regardless of the configured
	// value.
	LocalAdminOnly bool
	// PasswordComplexityEnabled: UNWIRED in OSS AND not settable via the
	// public API. No password validator reads this field; password
	// complexity rules apply (or do not apply) globally regardless of
	// the per-org configured value. The unwired
	// tools.IsStrongPassword helper enforces a fixed policy at every
	// call site.
	PasswordComplexityEnabled bool
	Active                    bool
	ComplianceContactEmail    *string

	// LastSCIMSyncAt records the most recent timestamp Identuum observed
	// a SCIM operation (Create/Replace/Delete user) against this org.
	// nil = no SCIM activity since the column was added.
	LastSCIMSyncAt *time.Time

	// E2EFixtureMarker is internal/local-test-only metadata populated by
	// the --e2e-create-org-admin-fixture CLI. NULL on every production
	// row and on every non-fixture row. The --e2e-purge-org-fixture CLI
	// requires this field to match an exact reserved literal before
	// hard-deleting the row, so a misuse of the bypass path cannot
	// destroy a real organization. Not projected onto any wire shape.
	E2EFixtureMarker *string
}

const (
	// AuthPolicyPermissive is the legacy-compatible default (empty string).
	// When AuthPolicy is empty, all authentication methods (local, LDAP, OIDC) are
	// permitted. This is intentional for backward-compatibility with rows that
	// pre-date the AuthPolicy column. All enforcement code handles this explicitly.
	AuthPolicyPermissive = ""
	AuthPolicyLocalOnly  = "local_only"
	AuthPolicyIDPOnly    = "idp_only"
	AuthPolicyMixed      = "mixed"
)

const (
	APIAuthPolicyStrict   = "STRICT"
	APIAuthPolicyImplicit = "IMPLICIT"
)

// Validate performs business logic validation on the Organization
func (o *Organization) Validate() error {
	// THE-UNVALIDATED-DOMAIN (2026-08-31), widened by owner ruling to EVERY
	// field: `Name == ""` accepted a name of pure whitespace and had no upper
	// bound, so an over-long name reached Postgres and came back as a driver
	// error instead of a clean refusal. Bounds match the live column widths
	// (organizations.name / .org_slug are VARCHAR(255)).
	if strings.TrimSpace(o.Name) == "" {
		return errors.New("name is required")
	}
	if len(o.Name) > organizationNameMaxLength {
		return fmt.Errorf("name must be %d characters or fewer", organizationNameMaxLength)
	}

	// THE-UNVALIDATED-DOMAIN (2026-08-31): `== ""` was the ENTIRE check, so
	// "lexus" — no dot, no TLD — was accepted and persisted. Validate() is
	// the choke point every create and update path already runs through, so
	// the grammar goes here rather than in one handler.
	if err := ValidateDomainFormat(o.Domain); err != nil {
		return err
	}

	// OrgSlug is OPTIONAL (many rows carry none), but when present it is an
	// identifier that appears in lookups, so it gets a grammar rather than
	// no check at all: lowercase letters, digits and hyphens, never
	// hyphen-edged. The live rows ("system-local", "saab") satisfy it.
	if slug := strings.TrimSpace(o.OrgSlug); slug != "" {
		if len(slug) > organizationSlugMaxLength {
			return fmt.Errorf("org_slug must be %d characters or fewer", organizationSlugMaxLength)
		}
		if slug[0] == '-' || slug[len(slug)-1] == '-' {
			return errors.New("org_slug must not start or end with a hyphen")
		}
		for i := 0; i < len(slug); i++ {
			c := slug[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return errors.New("org_slug may contain only lowercase letters, digits and hyphens")
			}
		}
	}

	// Tier is an enum; an unlisted value would silently render as TierBase
	// via Tier.String(), so an out-of-range value is refused rather than
	// quietly downgraded.
	if o.Tier != TierBase && o.Tier != TierPro && o.Tier != TierEnterprise {
		return errors.New("tier must be one of TierBase, TierPro or TierEnterprise")
	}

	// M2M anomaly thresholds are counts/seconds: negative is meaningless and
	// would otherwise reach the database unchallenged. Zero stays valid — it
	// is the "disabled" value the live rows use.
	if o.M2MAnomalyLimit < 0 {
		return errors.New("m2m_anomaly_limit must not be negative")
	}
	if o.M2MAnomalyWindowSeconds < 0 {
		return errors.New("m2m_anomaly_window_seconds must not be negative")
	}

	if o.MaxSessionsPerUser < 1 {
		return errors.New("max_sessions_per_user must be at least 1")
	}

	if o.MaxSessionsPerUser > 100 {
		return errors.New("max_sessions_per_user cannot exceed 100")
	}

	if o.MFAPolicy != "optional" && o.MFAPolicy != "required" {
		return errors.New("mfa_policy must be 'optional' or 'required'")
	}

	if o.ServiceAccountExpiryDays < 0 || o.ServiceAccountExpiryDays > 3650 {
		return errors.New("service_account_expiry_days must be between 0 (perpetual) and 3650")
	}

	// Validate AuthPolicy — AuthPolicyPermissive ("") is the explicit legacy default.
	if o.AuthPolicy != AuthPolicyPermissive &&
		o.AuthPolicy != AuthPolicyLocalOnly &&
		o.AuthPolicy != AuthPolicyIDPOnly &&
		o.AuthPolicy != AuthPolicyMixed {
		return errors.New("auth_policy must be one of 'local_only', 'idp_only', 'mixed', or '' (permissive default)")
	}

	// Validate ApiAuthorizationPolicy — empty string is accepted (defaults to STRICT at call-sites).
	if o.ApiAuthorizationPolicy != "" &&
		o.ApiAuthorizationPolicy != APIAuthPolicyStrict &&
		o.ApiAuthorizationPolicy != APIAuthPolicyImplicit {
		return errors.New("api_authorization_policy must be 'STRICT' or 'IMPLICIT'")
	}

	return nil
}

// CanAccess checks if the organization's tier allows a specific feature.
func (o *Organization) CanAccess(f Feature) bool {
	switch f {
	case FeatureWebhooks, FeatureAuditLog:
		return o.Tier >= TierPro
	default:
		return false
	}
}

// ValidateAdminAuth enforces strict Admin Sovereignty: privileged accounts
// (site_admin, org_admin) MUST authenticate via a credential that lives on
// the user's own device — local password (with MFA) or WebAuthn / FIDO2.
// External-IdP transports (OIDC, LDAP, AD, or any future federated method)
// are rejected unconditionally.
func ValidateAdminAuth(role string, method string) error {
	if role != string(RoleSiteAdmin) && role != string(RoleOrgAdmin) {
		return nil
	}
	if method == string(AuthMethodLocal) || method == string(AuthMethodWebAuthn) {
		return nil
	}
	return fmt.Errorf("compliance violation: %s must authenticate via local credentials or WebAuthn, not %q", role, method)
}

// CanAcceptNewUsers checks if organization can accept new user registrations
func (o *Organization) CanAcceptNewUsers() (bool, string) {
	if o.DeletedAt != nil {
		return false, "organization not found"
	}

	if !o.Active {
		return false, "organization not active"
	}

	return true, ""
}

// IsOperational checks if organization is operational (not deleted, is active)
func (o *Organization) IsOperational() bool {
	return o.DeletedAt == nil && o.Active
}
