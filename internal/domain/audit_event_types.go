package domain

// AuditEventTypeGroup groups related audit event type values for UI display.
// Used by the GET /api/v1/audit/event-types endpoint and coverage tests.
type AuditEventTypeGroup struct {
	Label string
	Types []AuditEventType
}

// AllAuditEventTypeGroups is the canonical grouped list of known audit event types.
// This is the single source of truth used by both the audit event-types API endpoint
// and drift-protection tests.
//
// MAINTENANCE: when adding a new AuditEventType constant above (audit.go), add it to
// the appropriate group here. The coverage test TestAllAuditEventTypeGroups_NoDuplicates
// and TestAllAuditEventTypeGroups_MinimumCount in audit_event_types_test.go will catch
// duplicates and mass-deletion regressions.
var AllAuditEventTypeGroups = []AuditEventTypeGroup{
	{"Authentication & sessions", []AuditEventType{
		"auth_success", "auth_failure", "logout",
		"session_created", "session_revoked", "session_expired",
		"self_sessions_revoked",
		"mfa_enabled", "mfa_disabled", "mfa_reset_by_admin",
		"step_up_triggered", "step_up_passed",
		"session_acr_uplifted", "session_acr_uplift_failed",
		"EMERGENCY_LOGIN_DETECTED", "concurrent_session_limit",
		"local_login_blocked_by_role", "session_revoked_anomaly",
		"session_evicted_max_sessions",
	}},
	{"Tokens", []AuditEventType{
		"token_issued", "token_refreshed", "token_revoked",
		"oauth_token.revoked",
		"token_introspected", "token_exchanged", "token_exchange",
		"par_request_created", "assertion_consumed",
	}},
	{"Users", []AuditEventType{
		"user_created", "bulk_user_created", "user_updated", "user_deleted",
		"user_restored", "user_activated", "user_deactivated",
		"password_changed", "role_changed", "site_admin_credentials_reset",
		"email_verified", "email_verification_resent",
		"invitation_consumed", "invitation_regenerated", "registration_approved",
		"user_password_reset_requested", "user_password_reset_completed",
	}},
	{"Organizations", []AuditEventType{
		"organization_created", "organization_updated", "organization_deleted",
		"organization_restored", "organization_activated", "organization_deactivated",
		"organization_admin_last_removed", "max_sessions_changed",
	}},
	{"Security & access", []AuditEventType{
		"data_accessed", "access_denied", "permission_denied",
		"security_violation", "rate_limit_exceeded",
		"anomaly_detected", "resource_not_found",
	}},
	{"OAuth & clients", []AuditEventType{
		"client_created", "client_updated", "client_deleted",
		"client_linked_service_account", "client_secret_rotated",
		"client_assertion_auth",
		"dynamic_client_registered", "dynamic_registration_token_issued",
		"service_account_created", "service_account_deleted",
	}},
	{"Identity providers", []AuditEventType{
		"identity_provider_created", "identity_provider_updated", "identity_provider_deleted",
		"consent_granted", "consent_denied",
		"directory_sync_completed", "directory_sync_failed",
	}},
	{"Passkeys & WebAuthn", []AuditEventType{
		"webauthn_credential_registered", "webauthn_credential_deleted", "webauthn_credential_renamed",
	}},
	{"RBAC", []AuditEventType{
		"rbac_role_created", "rbac_role_updated", "rbac_role_deleted",
		"rbac_role_assigned", "rbac_role_revoked",
		"rbac_role_scope_added", "rbac_role_scope_removed",
	}},
	{"API resources & scopes", []AuditEventType{
		"api_resource_created", "api_resource_updated", "api_resource_deleted", "api_resource_secret_rotated",
		"scope_template_created", "scope_template_updated", "scope_template_deleted",
	}},
	{"Webhooks", []AuditEventType{
		"webhook_endpoint_created", "webhook_endpoint_deleted", "webhook_signature_mismatch",
	}},
	{"SCIM", []AuditEventType{
		"scim_user_created", "scim_user_updated", "scim_user_deleted",
	}},
	{"MCP", []AuditEventType{
		"mcp_connection", "mcp_tool_called",
	}},
	{"Keys & credentials", []AuditEventType{
		"signing_key_generated", "signing_key_rotated", "signing_key_deprecated",
		"signing_key_deleted", "signing_key_reloaded", "signing_key_auto_rotated",
		"encryption_key_rotated", "smtp_credentials_rotated", "secret_rotation_failed",
	}},
	{"System & backups", []AuditEventType{
		"system_backup_completed", "system_backup_failed",
		"system_backup_initiated", "system_backup_rotation",
		"org_backup_initiated", "org_backup_completed", "org_backup_downloaded", "org_backup_purged",
		"org_backup_restore_started", "org_backup_restore_completed",
		"org_backup_restore_failed", "org_backup_sessions_revoked", "org_restored_from_backup",
		"compliance_attestation", "compliance_authorize_auto_delete",
	}},
	{"SPIFFE & federation", []AuditEventType{
		"spiffe_peer_created", "spiffe_peer_updated", "spiffe_peer_deleted",
		"spiffe_bundle_accepted", "spiffe_bundle_rejected",
		"spiffe_bundle_stale", "spiffe_bundle_unchanged",
		"spiffe_mapping_rule_created", "spiffe_mapping_rule_updated", "spiffe_mapping_rule_deleted",
		"spiffe_jit_sa_provisioned", "spiffe_svid_exchanged", "spiffe_svid_rejected",
	}},
}
