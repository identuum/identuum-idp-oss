package domain

import (
	"errors"
	"fmt"
)

var (
	// User Errors
	ErrUserNotFound          = errors.New("user not found")
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserInactive          = errors.New("user account inactive")
	ErrAmbiguousUser         = errors.New("multiple accounts found, organization slug required")
	ErrMultipleUsersFound    = errors.New("multiple users found")
	ErrNoWebAuthnCredentials = errors.New("no passkeys registered for this user")

	// Registration Errors
	ErrRegistrationDisabled        = errors.New("registration is not enabled for this organization")
	ErrOrganizationFull            = errors.New("organization cannot accept new users")
	ErrRegistrationPendingApproval = errors.New("registration is pending administrator approval")
	// ErrRegistrationDomainNotVerified surfaces when self-registration (or
	// OIDC/JIT provisioning) is attempted with an email whose domain has
	// not been verified for the target organization in the
	// organization_domains table (slice 6 of the org-admin Domains
	// feature). The same sentinel is returned when the verified row
	// exists but is owned by a different organization — the wire-facing
	// message MUST NOT distinguish those two cases (cross-org ownership
	// is a tenant secret). The server-side warn-log captures the true
	// reason for operator forensics.
	ErrRegistrationDomainNotVerified = errors.New("registration domain not verified for organization")

	// Organization Errors
	ErrOrganizationNotFound          = errors.New("organization not found")
	ErrOrganizationInactive          = errors.New("organization not active")
	ErrOrganizationAlreadyActive     = errors.New("organization already active")
	ErrOrganizationAlreadyExists     = errors.New("organization already exists")
	ErrOrganizationSlugAlreadyExists = errors.New("organization slug already exists")
	ErrOrgHasActiveUsers             = errors.New("cannot delete organization with active users")

	// Auth Policy Errors
	ErrLocalLoginDisabled = errors.New("local login disabled")
	ErrStrictReauthFailed = errors.New("strict re-authentication required")

	// Client Errors
	ErrClientNotFound = errors.New("client not found")
	// ErrClientNotLinkedToServiceAccount — the unlink path discovered
	// that the OAuth client is not currently linked to the requested
	// service account (either oauth_clients.service_account_id is NULL,
	// or it points at a DIFFERENT service account). Slice
	// identuum-20260530-service-account-oauth-client-unlink-backend
	// uses this sentinel so the handler can return a clean 409 Conflict
	// without leaking which-other-SA-the-client-is-linked-to.
	ErrClientNotLinkedToServiceAccount = errors.New("oauth client is not linked to the specified service account")
	ErrAuthCodeNotFound                = errors.New("auth code not found")
	ErrIDPNotFound                     = errors.New("identity provider not found")
	ErrAPIResourceAlreadyExists        = errors.New("api resource already exists")
	ErrAPIResourceNotFound             = errors.New("api resource not found")
	// ErrServiceAccountNameAlreadyExists — the create or update path
	// found another SA in the same organization already using the
	// requested name. Slice identuum-20260530-service-account-name-
	// conflict-backend uses this sentinel so the handler can return a
	// clean 409 Conflict. The public response message intentionally
	// does NOT disclose the conflicting SA's id — only that a name
	// collision occurred.
	ErrServiceAccountNameAlreadyExists = errors.New("service account name already exists")

	// Session Errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInvalid  = errors.New("session invalid")
	ErrSessionRevoked  = errors.New("session revoked")

	// Audit Errors
	ErrAuditEventNotFound = errors.New("audit event not found")

	// General
	ErrInternal           = errors.New("internal system error")
	ErrResourceNotFound   = errors.New("resource not found")
	ErrInvalidRequest     = errors.New("invalid request format")
	ErrForbidden          = errors.New("forbidden")
	ErrFeatureNotLicensed = errors.New("feature not available on current license tier")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidScope       = errors.New("invalid scope")
	ErrInvalidAudience    = errors.New("invalid audience")
	// ErrInvalidGrant — the OAuth grant request fails validation. RFC 6749 §5.2
	// invalid_grant. Used by RFC 8693 token-exchange and RFC 7523 jwt-bearer
	// (5.2.d) to collapse all subject-token / assertion validation failures
	// to a single wire-facing reason (no-enumeration discipline).
	ErrInvalidGrant       = errors.New("invalid grant")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenNotFound      = errors.New("token not found")
	ErrInvalidClientToken = errors.New("invalid client token")
	// ErrClientMismatch — the presented OAuth client is not the one to which
	// the refresh token was originally issued. §2.10 / RFC 6749 §10.4
	// cross-client replay protection. The /auth/revoke handler maps this to
	// an idempotent 200 per RFC 7009 §2.2 (silent no-op + log).
	ErrClientMismatch          = errors.New("oauth client does not own this token")
	ErrInvalidEmail            = errors.New("invalid email format")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrServiceUnavailable      = errors.New("service unavailable")
	ErrWeakPassword            = errors.New("password is too weak")
	ErrInvalidResetToken       = errors.New("invalid or expired reset token")
	ErrInvalidMFACode          = errors.New("invalid mfa code")
	ErrMFAUpdateRequired       = errors.New("mfa setup required")
	ErrMFARequiredByAdminRole  = errors.New("administrative roles must maintain MFA protection")
	ErrMFARequiredByOrgPolicy  = errors.New("organization policy requires MFA")
	// ErrMFAAlreadyEnrolled is returned by the authenticated MFA setup
	// endpoints when the calling user already has MFAEnabled=true. The
	// pending-login enrollment flow is the only path that legitimately
	// (re-)issues a TOTP secret without an explicit disable step;
	// account-settings re-enrollment must go through POST
	// /api/v1/me/mfa/disable first.
	// Without this guard, an attacker holding a valid authenticated
	// session for an MFA-enabled account could call /mfa/setup/initiate
	// to silently rotate the stored secret to one the attacker
	// controls. See internal/service/auth_service_mfa.go.
	ErrMFAAlreadyEnrolled        = errors.New("mfa already enrolled")
	ErrOrganizationSetupRequired = errors.New("organization setup required")
	ErrAdminDomainMismatch       = errors.New("admin email domain must match organization domain")
	ErrMfaRequiredForActivation  = errors.New("mfa enrollment is mandatory for organization activation")
	ErrPasswordChangeRequired    = errors.New("password change required")
	ErrOIDCLinkingRequired       = errors.New("oidc account linking required")
	// Org-scoped Backup & Restore errors (§10.A).
	// Sentinels are mapped to HTTP codes in the handler layer only; services
	// wrap these via fmt.Errorf("layer.action: %w", err) so errors.Is is stable
	// across wrapping.
	ErrOrgBackupOrgMismatch            = errors.New("org backup: organization id mismatch")
	ErrOrgBackupSchemaMismatch         = errors.New("org backup: schema version mismatch")
	ErrOrgBackupCorrupt                = errors.New("org backup: corrupt backup file")
	ErrOrgBackupNotFound               = errors.New("org backup: backup not found")
	ErrOrgBackupSystemOrg              = errors.New("org backup: not available for system organization")
	ErrOrgBackupRestoreConfirmRequired = errors.New("org backup: restore confirmation required")
	ErrOrgBackupStorageNotConfigured   = errors.New("org backup: storage not configured")
	ErrOrgBackupRestoreJobNotFound     = errors.New("org backup: restore job not found")
	ErrOrgBackupDecryptionFailed       = errors.New("org backup: decryption failed")
	ErrOrgBackupPasswordRequired       = errors.New("org backup: password required")
	ErrOrgBackupPasswordTooWeak        = errors.New("org backup: password too weak")
	ErrOrgBackupLimitReached           = errors.New("org backup: per-organization backup limit reached")
	ErrOrgBackupActorEmailCollision    = errors.New("org backup: actor email collides with envelope user")
	ErrOrgBackupOrgSoftDeleted         = errors.New("org backup: target organization is soft-deleted")
	ErrOrgBackupRateLimited            = errors.New("org backup: rate limited")
	// ErrOrgBackupIncompatibleVersion — the backup's envelope_version does not
	// match this build's domain.OrgBackupEnvelopeVersion. Distinct from
	// ErrOrgBackupCorrupt so callers (admin UI, restore handler, audit
	// emission) can render a version-mismatch path that points the operator
	// at re-creating the backup against the running schema, instead of the
	// generic "corrupt file" path. Use errors.Is to test for it across
	// wrappings.
	ErrOrgBackupIncompatibleVersion = errors.New("org backup: incompatible envelope version")

	// ErrServiceAccountNameTaken — another LIVE service account in the same
	// organization already carries this name (unique index
	// uq_service_accounts_org_name_live, migration 0030). Handlers map it to
	// 409 so the UI's inline name-conflict path is reachable (v0.3.2 gap E).
	ErrServiceAccountNameTaken = errors.New("service account: name already taken in this organization")
)

var (
	ErrOrganizationNotEmpty = fmt.Errorf("organization is not empty")
	// ErrOrganizationHasAdmin is returned by GenerateClaimToken when the target
	// organization already has at least one active (non-deleted, non-banned)
	// org_admin user. site_admin may only issue a delegation URL when the org
	// has zero active org_admins.
	ErrOrganizationHasAdmin = fmt.Errorf("organization already has an active org admin")
	ErrClaimExpired         = fmt.Errorf("claim expired")
	ErrClaimNotFound        = fmt.Errorf("claim not found")
	// ErrEmailVerificationAlreadyUsed is returned when MarkAsUsed matches zero
	// rows — a concurrent verification already burned the token. It is a RACE
	// OUTCOME, not a storage failure (P3-1/P3-2 class, third instance).
	ErrEmailVerificationAlreadyUsed = fmt.Errorf("email verification token already used")
	ErrClaimAlreadyConsumed         = fmt.Errorf("claim already consumed")
	ErrClaimMaxAttemptsReached      = fmt.Errorf("claim max password attempts reached")
)

// External-IdP / Trusted Assertion Issuer sentinels.
// and Phase D mapping table.
var (
	ErrAssertionIssuerUnknown    = errors.New("assertion_issuer_unknown")
	ErrAssertionIssuerDisabled   = errors.New("assertion_issuer_disabled")
	ErrAssertionSignatureInvalid = errors.New("assertion_signature_invalid")
	ErrAssertionClaimsInvalid    = errors.New("assertion_claims_invalid")
	// ErrAssertionAudienceMismatch — the assertion's `aud` claim doesn't
	// match the IdP's token endpoint URL or any entry in the trust's
	// AcceptableAudiences list. Phase 5.2.d (RFC 7523 jwt-bearer).
	ErrAssertionAudienceMismatch = errors.New("assertion_audience_mismatch")
	// ErrAssertionReplay — a replay attempt: the (trust, jti) pair was
	// seen within the validity window. Atomic detection via Redis SETNX.
	// Phase 5.2.d.
	ErrAssertionReplay = errors.New("assertion_replay")
	// ErrAssertionSubjectMappingMiss — the trust's SubjectClaimMapping
	// resolves to no IdP user or service account. v1 has no auto-
	// provisioning. Phase 5.2.d.
	ErrAssertionSubjectMappingMiss = errors.New("assertion_subject_mapping_miss")
	// ErrAssertionCrossTenantDenied — the resolved subject's org doesn't
	// match the trust's org and the trust isn't platform-wide. Phase 5.2.d.
	ErrAssertionCrossTenantDenied = errors.New("assertion_cross_tenant_denied")
	ErrShadowUserNotProvisioned   = errors.New("shadow_user_not_provisioned")
	ErrShadowUserDisabled         = errors.New("shadow_user_disabled")

	// Repository-layer not-found for trusted-issuer rows. Distinct from
	// ErrAssertionIssuerUnknown — the latter is the wire-facing reason
	// that surfaces when the (org, iss) pair has no enabled match during
	// assertion verification (Phase D); this sentinel is the storage-layer
	// signal that lookup found no matching row at all.
	ErrTrustedAssertionIssuerNotFound = errors.New("trusted assertion issuer not found")
	// ErrTrustedAssertionIssuerConflict surfaces when Create runs into the
	// (organization_id, issuer) unique index. Mapped to 409 by the admin
	// handler.
	ErrTrustedAssertionIssuerConflict = errors.New("trusted assertion issuer already exists for this issuer URL in this organization")

	// Per-org idp_only policy: role-aware local-credential reject.
	// and §13.9.
	//
	// ErrLocalLoginDisabledForRole — internal-only sentinel raised when
	// a RoleOrgUser attempts a local-credential flow in an org with
	// auth_policy=idp_only. NEVER reaches the wire (per §13.3 enumeration
	// protection): handlers using IsLocalCredentialFlowAllowed translate
	// this to the same generic invalid_credentials envelope a wrong-password
	// attempt would produce. The sentinel exists so audit emission and
	// structured logs can record the true reason.
	ErrLocalLoginDisabledForRole = errors.New("local login disabled for this role: org auth_policy requires external IdP")

	// Phase F: consent-UI on-demand federation sentinels.
	// 	//
	// ErrConsentFederationNotConfigured — the org has zero trusted
	// assertion issuers registered AND there is no Identuum-IdP path
	// configured. Cannot federate; the user must be onboarded via SCIM
	// before consent can be collected. Maps to 503 service_unavailable
	// at the wire so the UI can show a clear "ask your admin" page.
	ErrConsentFederationNotConfigured = errors.New("consent federation not configured for this organization")
	// ErrConsentFederationIssuerAmbiguous — the org has more than one
	// enabled trusted assertion issuer registered and no default has
	// been chosen (the default_consent_idp_id column is a deferred
	// follow-up; until it lands the resolution rule requires exactly
	// one enabled row). Maps to 503 with a description that points
	// admins at the trusted-issuer settings page.
	ErrConsentFederationIssuerAmbiguous = errors.New("multiple trusted assertion issuers registered; no default consent IdP selected")
)

// SPIFFE Federation sentinels — wire-facing reason codes for the JWT-SVID
// branch of the RFC 8693 token-exchange endpoint and admin CRUD surface.
// Per docs/ImplementationPlan-SPIFFEFederation.md §4 / §5.
var (
	ErrSPIFFEPeerUnknown            = errors.New("spiffe_peer_unknown")
	ErrSPIFFEPeerDisabled           = errors.New("spiffe_peer_disabled")
	ErrSPIFFEBundleStale            = errors.New("spiffe_bundle_stale")
	ErrSPIFFESVIDInvalid            = errors.New("spiffe_svid_invalid")
	ErrSPIFFENoMappingMatch         = errors.New("spiffe_no_mapping_match")
	ErrSPIFFEMappingDisabled        = errors.New("spiffe_mapping_disabled")
	ErrSPIFFEScopeIntersectionEmpty = errors.New("spiffe_scope_intersection_empty")

	// Repository-layer not-found / conflict sentinels — distinct from the
	// wire-facing peer-unknown error so handlers can disambiguate admin
	// CRUD failures (404 / 409) from token-exchange failures (401).
	ErrSPIFFEPeerNotFound        = errors.New("spiffe federation peer not found")
	ErrSPIFFEPeerConflict        = errors.New("spiffe federation peer already exists for this trust domain in this organization")
	ErrSPIFFEMappingRuleNotFound = errors.New("spiffe mapping rule not found")
	ErrSPIFFEBundleNotFound      = errors.New("spiffe trust bundle not found")
	// ErrSPIFFEPullDisabled is returned when an operator-triggered pull
	// refresh runs into either the global air-gap kill switch or a per-
	// peer air_gap_only=TRUE flag.
	ErrSPIFFEPullDisabled = errors.New("spiffe pull mode is disabled")
	// ErrSPIFFEPeerLimitExceeded is returned when peer creation would push
	// an org past its tier-defined LimitSPIFFEPeers cap.
	ErrSPIFFEPeerLimitExceeded = errors.New("spiffe peer limit exceeded for this license tier")
)
