package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditEventType identifies the type of action performed.
//
// 4.4g.4a re-narrowing: AG audit-event constants removed (agent session
// lifecycle, HITL, agent intervention, decision polling/capability, agent
// chain extension, agent token issuance, agent consent, agent issuance
// settings, ITDR anomaly events, fail-closed triggers, compensation log,
// gateway resource / completion / denial, agent vault credential, LLM
// model catalog, ID-JAG, trusted-assertion-issuer, consent federation,
// assertion accepted/rejected, SPIFFE federation, session-budget). AG
// audit emission lives in identuum-ag.
type AuditEventType string

const (
	// Authentication events
	AuditAuthSuccess    AuditEventType = "auth_success"
	AuditAuthFailure    AuditEventType = "auth_failure"
	AuditTokenIssued    AuditEventType = "token_issued"
	AuditTokenRefreshed AuditEventType = "token_refreshed"
	AuditTokenRevoked   AuditEventType = "token_revoked"
	// AuditOAuthTokenRevoked — RFC 7009 /api/v1/oauth/revoke
	// success path. Distinct from the generic AuditTokenRevoked so
	// audit-log readers can separate OAuth-spec revocations
	// (handler-emitted on a successful verifier hit) from any
	// internal token-revoked event. The string value
	// "oauth_token.revoked" is preserved verbatim because external
	// log consumers already filter on it; the dot-form is
	// intentional and must not be normalized to underscore form.
	// Metadata fields: client_id, client_kind, optionally
	// token_kind="refresh_token" on the refresh-revoke branch.
	// NEVER carries the raw token, validator hash, JTI, or session
	// material.
	AuditOAuthTokenRevoked AuditEventType = "oauth_token.revoked"
	AuditTokenIntrospected AuditEventType = "token_introspected"
	// AuditTokenExchanged — RFC 8693 token-exchange success. Phase 5.2.c.
	// Metadata fields: requesting_client_id, original_scope, issued_scope,
	// audience, subject_token_type.
	AuditTokenExchanged AuditEventType = "token_exchanged"
	// AuditAssertionConsumed — RFC 7523 jwt-bearer assertion successfully
	// validated and consumed. Phase 5.2.d. Metadata fields: trust_id,
	// assertion_jti, mapped_subject_id, mapped_subject_kind (user/sa),
	// scope, requesting_client_id.
	AuditAssertionConsumed   AuditEventType = "assertion_consumed"
	AuditSessionCreated      AuditEventType = "session_created"
	AuditSessionRevoked      AuditEventType = "session_revoked"
	AuditSelfSessionsRevoked AuditEventType = "self_sessions_revoked"
	AuditLogout              AuditEventType = "logout"
	AuditSessionExpired      AuditEventType = "session_expired"
	AuditMFAEnabled          AuditEventType = "mfa_enabled"
	AuditMFADisabled         AuditEventType = "mfa_disabled"
	// AuditOrgAdminMFAReset is emitted when site_admin clears an
	// org_admin's MFA via the operator-recovery endpoint. Distinct from
	// AuditMFADisabled (self-service or org_admin → org_user reset) so
	// the audit log distinguishes infrastructure-authority recovery
	// from routine operator resets. Metadata carries the target
	// user_id and org_id; never the cleared TOTP secret.
	AuditOrgAdminMFAReset AuditEventType = "org_admin_mfa_reset"
	AuditEmergencyAccess  AuditEventType = "EMERGENCY_LOGIN_DETECTED"

	// User management
	AuditUserCreated                AuditEventType = "user_created"
	AuditBulkUserCreated            AuditEventType = "bulk_user_created"
	AuditUserUpdated                AuditEventType = "user_updated"
	AuditUserDeleted                AuditEventType = "user_deleted"
	AuditUserRestored               AuditEventType = "user_restored"
	AuditUserActivated              AuditEventType = "user_activated"
	AuditUserDeactivated            AuditEventType = "user_deactivated"
	AuditEmailVerified              AuditEventType = "email_verified"
	AuditEmailVerificationResent    AuditEventType = "email_verification_resent"
	AuditPasswordChanged            AuditEventType = "password_changed"
	AuditRoleChanged                AuditEventType = "role_changed"
	AuditUserPasswordResetRequested AuditEventType = "user_password_reset_requested"
	AuditUserPasswordResetCompleted AuditEventType = "user_password_reset_completed"
	AuditInvitationConsumed         AuditEventType = "invitation_consumed"
	AuditRegistrationApproved       AuditEventType = "registration_approved"

	// Organization management
	AuditOrgCreated     AuditEventType = "organization_created"
	AuditOrgUpdated     AuditEventType = "organization_updated"
	AuditOrgDeleted     AuditEventType = "organization_deleted"
	AuditOrgRestored    AuditEventType = "organization_restored"
	AuditOrgActivated   AuditEventType = "organization_activated"
	AuditOrgDeactivated AuditEventType = "organization_deactivated"
	// AuditOrgAdminLastRemoved is emitted when an organization is automatically
	// disabled because its last active org_admin was removed, banned, or deleted
	// by site_admin. The organization can be re-claimed via the explicit invitation
	// endpoint (POST /organizations/:id/invitations).
	AuditOrgAdminLastRemoved AuditEventType = "organization_admin_last_removed"
	AuditMaxSessionsChanged  AuditEventType = "max_sessions_changed"

	// Organization domain lifecycle. Slice 1 reserves the constants;
	// emission lands in the slice that introduces the mutation handlers.
	// Metadata fields are pinned here so call sites stay consistent:
	//   AuditOrgDomainAdded                — organization_id, domain_id, domain
	//   AuditOrgDomainVerificationStarted  — organization_id, domain_id, domain
	//   AuditOrgDomainVerified             — organization_id, domain_id, domain
	//   AuditOrgDomainVerificationFailed   — organization_id, domain_id, domain, reason
	//   AuditOrgDomainRemoved              — organization_id, domain_id, domain
	//   AuditOrgDomainPrimaryChanged       — organization_id, old_domain_id, new_domain_id, domain
	// The verification-token VALUE is NEVER part of any of these metadata
	// fields — only its lifecycle state is observable.
	AuditOrgDomainAdded               AuditEventType = "organization_domain_added"
	AuditOrgDomainVerificationStarted AuditEventType = "organization_domain_verification_started"
	AuditOrgDomainVerified            AuditEventType = "organization_domain_verified"
	AuditOrgDomainVerificationFailed  AuditEventType = "organization_domain_verification_failed"
	AuditOrgDomainRemoved             AuditEventType = "organization_domain_removed"
	AuditOrgDomainPrimaryChanged      AuditEventType = "organization_domain_primary_changed"

	// Org-scoped Backup & Restore audit events.
	AuditOrgBackupInitiated        AuditEventType = "org_backup_initiated"
	AuditOrgBackupCompleted        AuditEventType = "org_backup_completed"
	AuditOrgBackupDownloaded       AuditEventType = "org_backup_downloaded"
	AuditOrgBackupRestoreStarted   AuditEventType = "org_backup_restore_started"
	AuditOrgBackupRestoreCompleted AuditEventType = "org_backup_restore_completed"
	AuditOrgBackupRestoreFailed    AuditEventType = "org_backup_restore_failed"
	AuditOrgBackupSessionsRevoked  AuditEventType = "org_backup_sessions_revoked"
	AuditOrgRestoredFromBackup     AuditEventType = "org_restored_from_backup"
	AuditOrgBackupPurged           AuditEventType = "org_backup_purged"

	AuditComplianceAttestation AuditEventType = "compliance_attestation"
	AuditAuthorizeAutoDelete   AuditEventType = "compliance_authorize_auto_delete"

	// Key management
	AuditKeyGenerated   AuditEventType = "signing_key_generated"
	AuditKeyRotated     AuditEventType = "signing_key_rotated"
	AuditKeyDeprecated  AuditEventType = "signing_key_deprecated"
	AuditKeyDeleted     AuditEventType = "signing_key_deleted"
	AuditKeyReloaded    AuditEventType = "signing_key_reloaded"
	AuditKeyAutoRotated AuditEventType = "signing_key_auto_rotated"

	// M2M / Service Accounts
	//
	// Resource-subject scoped events (slice
	// identuum-20260530-org-admin-service-account-recent-activity-backend):
	// every AuditServiceAccount* row carries subject_type="service_account"
	// and subject_id=<service account's INTERNAL UUID> so the org-admin
	// service-account detail page can mount a Recent activity card
	// filtered by subject_id=<sa.ID>. Tenant scoping continues to flow
	// through actor_organization_id, set by prepareEvent from the actor.
	//
	// AuditServiceAccountLinkedOAuthClient is the service-account-scoped
	// peer of the existing AuditClientLinkedServiceAccount (which carries
	// subject_type="oauth_client"). Both events fire on the same link
	// mutation so both surfaces — the SA detail page and the OAuth client
	// detail page — can render the link in their resource-scoped Recent
	// activity cards.
	AuditServiceAccountCreated             AuditEventType = "service_account_created"
	AuditServiceAccountDeleted             AuditEventType = "service_account_deleted"
	AuditServiceAccountLinkedOAuthClient   AuditEventType = "service_account_linked_oauth_client"
	AuditServiceAccountUnlinkedOAuthClient AuditEventType = "service_account_unlinked_oauth_client"
	// AuditServiceAccountDisabled / AuditServiceAccountEnabled (slice
	// identuum-20260530-service-account-disable-enable-backend). Both
	// carry subject_type="service_account" + subject_id=sa.ID and safe
	// metadata {service_account_id, service_account_name, role,
	// organization_id, previous_active, active}. NEVER include any
	// credential / hash / private-key / token / cookie field.
	AuditServiceAccountDisabled AuditEventType = "service_account_disabled"
	AuditServiceAccountEnabled  AuditEventType = "service_account_enabled"
	// AuditServiceAccountUpdated (slice identuum-20260530-service-
	// account-edit-backend). Carries subject_type="service_account" +
	// subject_id=sa.ID and safe metadata {service_account_id,
	// service_account_name, role, organization_id, previous_name,
	// previous_description_changed, previous_role, new_name,
	// new_description_changed, new_role, active}. The description
	// uses boolean *_changed markers rather than the full prose to
	// avoid silently capturing potentially-sensitive metadata in the
	// audit row. NEVER include any credential / hash / private-key /
	// token / cookie field.
	AuditServiceAccountUpdated AuditEventType = "service_account_updated"
	AuditTokenExchange         AuditEventType = "token_exchange"

	// MCP — IdP-management MCP server (no agent action surfaces).
	AuditMCPConnection AuditEventType = "mcp_connection"
	AuditMCPToolCalled AuditEventType = "mcp_tool_called"

	// AuditClientAssertionAuth — private_key_jwt client assertion successfully
	// verified and consumed. Phase 7.3.b. Metadata fields: client_id, jti.
	AuditClientAssertionAuth AuditEventType = "client_assertion_auth"

	// Client / API resource / scope template / RBAC management
	AuditClientCreated              AuditEventType = "client_created"
	AuditClientUpdated              AuditEventType = "client_updated"
	AuditClientDeleted              AuditEventType = "client_deleted"
	AuditClientSecretRotated        AuditEventType = "client_secret_rotated"
	AuditClientLinkedServiceAccount AuditEventType = "client_linked_service_account"
	// AuditClientUnlinkedServiceAccount is the OAuth-client-scoped peer
	// of AuditServiceAccountUnlinkedOAuthClient. Both events fire on the
	// same unlink mutation (slice identuum-20260530-service-account-
	// oauth-client-unlink-backend) so the OAuth-client Recent activity
	// card and the service-account Recent activity card both surface the
	// unlink. The OAuth-client-scoped event carries subject_type=
	// "oauth_client" + subject_id=client.ID; metadata.service_account_id
	// records WHICH SA the client used to be linked to.
	AuditClientUnlinkedServiceAccount AuditEventType = "client_unlinked_service_account"

	AuditAPIResourceCreated       AuditEventType = "api_resource_created"
	AuditAPIResourceUpdated       AuditEventType = "api_resource_updated"
	AuditAPIResourceDeleted       AuditEventType = "api_resource_deleted"
	AuditAPIResourceSecretRotated AuditEventType = "api_resource_secret_rotated"

	AuditScopeTemplateCreated AuditEventType = "scope_template_created"
	AuditScopeTemplateUpdated AuditEventType = "scope_template_updated"
	AuditScopeTemplateDeleted AuditEventType = "scope_template_deleted"

	AuditRBACRoleCreated      AuditEventType = "rbac_role_created"
	AuditRBACRoleUpdated      AuditEventType = "rbac_role_updated"
	AuditRBACRoleDeleted      AuditEventType = "rbac_role_deleted"
	AuditRBACRoleScopeAdded   AuditEventType = "rbac_role_scope_added"
	AuditRBACRoleScopeRemoved AuditEventType = "rbac_role_scope_removed"
	AuditRBACRoleAssigned     AuditEventType = "rbac_role_assigned"
	AuditRBACRoleRevoked      AuditEventType = "rbac_role_revoked"

	// Generic security/anomaly events
	AuditRateLimitExceeded AuditEventType = "rate_limit_exceeded"
	AuditConcurrentSession AuditEventType = "concurrent_session_limit"
	AuditAccessDenied      AuditEventType = "access_denied"
	AuditPermissionDenied  AuditEventType = "permission_denied"
	AuditResourceNotFound  AuditEventType = "resource_not_found"
	AuditSecurityViolation AuditEventType = "security_violation"
	AuditAnomalyDetected   AuditEventType = "anomaly_detected"

	// Secret rotation events
	AuditEncryptionKeyRotated   AuditEventType = "encryption_key_rotated"
	AuditSMTPCredentialsRotated AuditEventType = "smtp_credentials_rotated"
	AuditSecretRotationFailed   AuditEventType = "secret_rotation_failed"

	AuditSystemBackupCompleted AuditEventType = "system_backup_completed"
	AuditSystemBackupInitiated AuditEventType = "system_backup_initiated"
	AuditStepUpTriggered       AuditEventType = "step_up_triggered"
	AuditStepUpPassed          AuditEventType = "step_up_passed"

	// Session ACR uplift events
	AuditSessionACRUplifted     AuditEventType = "session_acr_uplifted"
	AuditSessionACRUpliftFailed AuditEventType = "session_acr_uplift_failed"
	AuditSessionRevokedAnomaly  AuditEventType = "session_revoked_anomaly"
	AuditSystemBackupFailed     AuditEventType = "system_backup_failed"
	AuditSystemBackupRotation   AuditEventType = "system_backup_rotation"

	// Directory sync
	AuditDirectorySyncCompleted AuditEventType = "directory_sync_completed"
	AuditDirectorySyncFailed    AuditEventType = "directory_sync_failed"

	// Identity Provider Management
	AuditIDPCreated AuditEventType = "identity_provider_created"
	AuditIDPUpdated AuditEventType = "identity_provider_updated"
	AuditIDPDeleted AuditEventType = "identity_provider_deleted"

	// Webhook Management
	AuditWebhookEndpointCreated   AuditEventType = "webhook_endpoint_created"
	AuditWebhookEndpointDeleted   AuditEventType = "webhook_endpoint_deleted"
	AuditWebhookSignatureMismatch AuditEventType = "webhook_signature_mismatch"

	// Bulk data access
	AuditDataAccessed AuditEventType = "data_accessed"

	// WebAuthn / Passkey Management
	AuditWebAuthnCredentialRegistered AuditEventType = "webauthn_credential_registered" //nolint:gosec // G101 false positive: audit event type identifier, not a credential
	AuditWebAuthnCredentialDeleted    AuditEventType = "webauthn_credential_deleted"    //nolint:gosec // G101 false positive

	// Dynamic Client Registration (RFC 7591)
	AuditDynamicClientRegistered        AuditEventType = "dynamic_client_registered"
	AuditDynamicRegistrationTokenIssued AuditEventType = "dynamic_registration_token_issued"

	// OIDC consent decisions
	AuditConsentGranted AuditEventType = "consent_granted"
	AuditConsentDenied  AuditEventType = "consent_denied"

	// Emitted when org_user local credential flow is blocked by org auth_policy=idp_only.
	AuditLocalLoginBlockedByRole AuditEventType = "local_login_blocked_by_role"

	// Emitted when an existing user session is forcibly revoked to make
	// room under the organization's max_sessions_per_user cap during
	// new-session creation. Wired by slice
	// agent-a-20260714-idp-oss-maxsessions-eviction-enforcement
	// (Decision D-015 §4). Best-effort eviction — does NOT block the
	// new-session-create call. site_admin and org_admin users are
	// exempt per the locked admin-local invariant (Decision D-004) so
	// this event NEVER fires for admin roles.
	AuditSessionEvictedMaxSessions AuditEventType = "session_evicted_max_sessions"

	// Emitted by the operator credential-recovery CLI command when site_admin
	// credentials are reset outside the normal authentication flow.
	AuditSiteAdminCredentialsReset AuditEventType = "site_admin_credentials_reset" // #nosec G101 -- audit event type label string, not a credential value.

	// Emitted during the first-login MFA enrollment flow for eligible users.
	AuditMFAEnrolled AuditEventType = "mfa_enrolled"
)

// AuditEventPriority defines the urgency/importance of an audit event
type AuditEventPriority string

const (
	AuditPriorityCritical AuditEventPriority = "critical"
	AuditPriorityHigh     AuditEventPriority = "high"
	AuditPriorityNormal   AuditEventPriority = "normal"
	AuditPriorityLow      AuditEventPriority = "low"
)

// AuditEvent represents a security-relevant event within the system.
type AuditEvent struct {
	CreatedAt           time.Time
	SubjectType         *string
	FilterOrgID         *uuid.UUID
	Metadata            map[string]any
	ActorEmail          *string
	ActorRole           *string
	ActorOrganizationID *uuid.UUID
	ActorID             *uuid.UUID
	SubjectID           *uuid.UUID
	SubjectEmail        *string
	RequestID           *string
	IPAddress           *string
	UserAgent           *string
	// Outcome wires the audit.outcome column — the success/denied/error
	// discriminator. NULL when the emitting audit.Event left Outcome empty.
	Outcome *string
	// CorrelationID wires the audit.correlation_id column. NULL when the
	// caller did not supply X-Correlation-ID.
	CorrelationID *string
	ActorType     string
	Priority      AuditEventPriority
	EventType     AuditEventType
	ID            uuid.UUID
}

// AuditFilters defines query filters for audit event retrieval.
type AuditFilters struct {
	ActorID     *uuid.UUID
	ActorOrgID  *uuid.UUID
	SubjectType *string
	SubjectID   *uuid.UUID
	EventType   *AuditEventType
	// Outcome filters on the success/denied/error discriminator (L-2 read
	// API). NULL-outcome rows never match a non-nil Outcome filter.
	Outcome       *string
	EventTypes    []AuditEventType
	IPAddress     *string
	StartDate     *time.Time
	EndDate       *time.Time
	SortColumn    string
	SortOrder     string
	Limit         int
	Offset        int
	ActorType     *string
	CorrelationID *string
}

// Claim management audit event identifiers.
const (
	AuditClaimGenerated     = "claim.generated"
	AuditClaimAutoGenerated = "claim.auto_generated"
	AuditClaimConsumed      = "claim.consumed"
	// AuditClaimConsumptionPartial is emitted when ConsumeClaim's side
	// effects partially fail.
	AuditClaimConsumptionPartial = "claim.consumption_partial"
	// AuditClaimEmailSendAttempted is emitted after the notification service
	// attempts to deliver the delegation URL to the recipient's email address.
	// Metadata includes email_sent (bool), target_email, and failure_category
	// if the attempt failed. Raw URLs and tokens are never included.
	AuditClaimEmailSendAttempted = "claim.email_send_attempted"
	// AuditClaimURLDisplayed is emitted when the delegation URL is included in
	// the API response, indicating the site_admin received it for out-of-band
	// delivery. Raw URLs and tokens are never included in metadata.
	AuditClaimURLDisplayed = "claim.url_displayed"
)

// SPIFFE Federation audit event identifiers (sourced verbatim from legacy
// auth-service/internal/domain/audit.go). The 4.6.5a SPIFFE code-path audit's
// INTACT scan enumerated the SPIFFE *type* files but missed these constants,
// which live alongside other audit-event identifiers — surfaced and added
// during the 4.6.5b2 service-layer port that emits them.
//
// Peer / mapping-rule mutations carry: peer_id, trust_domain, name, optional
// bundle_endpoint_url, enabled, air_gap_only; updates additionally include
// changed_fields []string. Bundle events carry peer_id, version,
// sha256_prefix (first 16 hex chars), source, key_count, expires_at, optional
// actor_user_id (NULL for pull). SVID exchange events carry peer_id,
// trust_domain, spiffe_id, audience, scopes_granted, service_account_id,
// client_id, optional agent_session_id, and bundle_version_used; rejected
// events drop service_account_id and add reason_code (the internal sentinel
// string).
const (
	AuditSPIFFEPeerCreated        AuditEventType = "spiffe_peer_created"
	AuditSPIFFEPeerUpdated        AuditEventType = "spiffe_peer_updated"
	AuditSPIFFEPeerDeleted        AuditEventType = "spiffe_peer_deleted"
	AuditSPIFFEBundleAccepted     AuditEventType = "spiffe_bundle_accepted"
	AuditSPIFFEBundleRejected     AuditEventType = "spiffe_bundle_rejected"
	AuditSPIFFEBundleUnchanged    AuditEventType = "spiffe_bundle_unchanged"
	AuditSPIFFEBundleStale        AuditEventType = "spiffe_bundle_stale"
	AuditSPIFFEMappingRuleCreated AuditEventType = "spiffe_mapping_rule_created"
	AuditSPIFFEMappingRuleUpdated AuditEventType = "spiffe_mapping_rule_updated"
	AuditSPIFFEMappingRuleDeleted AuditEventType = "spiffe_mapping_rule_deleted"
	AuditSPIFFESVIDExchanged      AuditEventType = "spiffe_svid_exchanged"
	AuditSPIFFESVIDRejected       AuditEventType = "spiffe_svid_rejected"
	AuditSPIFFEJITSAProvisioned   AuditEventType = "spiffe_jit_sa_provisioned"
)
