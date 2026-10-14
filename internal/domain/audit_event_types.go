package domain

import "strings"

// AuditEventTypeGroup groups related audit event type values for UI display.
// Served by GET /api/v1/audit/event-types (the console's event-type filter).
type AuditEventTypeGroup struct {
	Label string
	Types []AuditEventType
}

// AllAuditEventTypeGroups lists exactly the event_type values this server
// can record, grouped in plain words. The console's event-type filter is
// built from it, so a name missing here cannot be picked and a name listed
// here that nothing records offers an empty result.
//
// MAINTENANCE: TestAuditEventTypeCatalog_MatchesRecordedNames reads every
// audit.Event Action in the module and fails on a recorded name missing here
// and on a name here that nothing records. Add a new name to the group it
// belongs to; never rename a recorded name (stored rows keep the old one).
// Labels come from AuditEventTypeLabel, never from a hand list.
var AllAuditEventTypeGroups = []AuditEventTypeGroup{
	{"Sign-in", []AuditEventType{
		"auth.oidc_login.failure", "auth.oidc_login.success", "auth.oidc_login_initiated",
		"local_login_blocked_by_role",
		"user_session.browser_login.failure", "user_session.browser_login.success",
		"user_session.login.failure", "user_session.login.success",
		"user_session.login.mfa_enroll_complete_failure", "user_session.login.mfa_enrolled",
		"user_session.login.mfa_enrollment_required", "user_session.login.mfa_pending_create_failure",
		"user_session.login.mfa_recovery_code_consumed", "user_session.login.mfa_required",
		"user_session.login.mfa_verified", "user_session.login.mfa_verify_failure",
		"user_session.login.password_change_required", "user_session.login.password_changed",
		"user_session.login.password_expired",
		"user_session.login.webauthn_failure", "user_session.login.webauthn_mfa_required",
		"user_session.login.webauthn_policy_denied", "user_session.login.webauthn_success",
		"user_session.step_up.failure", "user_session.step_up.passkey_failure",
		"user_session.step_up.passkey_success", "user_session.step_up.success",
	}},
	{"Sessions and sign-out", []AuditEventType{
		"backchannel_logout_delivery.replayed",
		"self_sessions_revoked", "session_evicted_max_sessions", "session_revoked",
		"user_session.backchannel_logout.delivered", "user_session.frontchannel_logout",
		"user_session.logout", "user_session.logout.cookie_revoked",
		"user_session.logout.redirected", "user_session.logout.revocation_unconfirmed",
		"user_session.refresh.reuse_detected", "user_session.refresh.success",
		"user_session.revoke.success",
	}},
	{"Multi-factor and passkeys", []AuditEventType{
		"mfa_disabled", "org_admin_mfa_reset",
		"user_session.mfa.recovery_codes_regenerated", "user_session.mfa.self_enrolled",
		"user_session.mfa.self_enrollment_started",
		"webauthn_credential_deleted", "webauthn_credential_registered",
	}},
	{"Users", []AuditEventType{
		"email_verification_resent", "email_verified", "password_changed", "profile.updated",
		"user.created", "user.deleted", "user.invite_redeemed", "user.invite_reissued",
		"user.invited", "user.password_reset_link_issued", "user.registration_approved",
		"user.registration_rejected", "user.restored", "user.self_registered",
		"site_admin_credentials_reset",
		"user.self_registration_refused", "user.updated",
		"user_activated", "user_created", "user_deactivated",
		"user_password_reset_completed", "user_password_reset_requested",
	}},
	{"Organizations", []AuditEventType{
		"org.identity_provider_created", "org.identity_provider_deleted",
		"org.identity_provider_updated", "org.protocol_settings_changed",
		"organization.activation_token_resent", "organization.created", "organization.deleted",
		"organization.initial_admin_failed", "organization.registration_updated",
		"organization.restored", "organization.updated", "organization_activated",
		"organization_domain.created", "organization_domain.deleted",
		"organization_domain.set_primary", "organization_domain.verified",
	}},
	{"Roles and scopes", []AuditEventType{
		"org_role.assigned", "org_role.created", "org_role.deleted", "org_role.scope_added",
		"org_role.scope_removed", "org_role.unassigned", "org_role.updated",
		"scope.denied",
		"scope_template.created", "scope_template.deleted", "scope_template.updated",
	}},
	{"Applications and APIs", []AuditEventType{
		"api_resource.created", "api_resource.deleted", "api_resource.secret_rotated",
		"api_resource.updated",
		"client.created", "client.dcr_registered", "client.deleted", "client.secret_rotated",
		"client.updated",
		"dcr.client_deleted", "dcr.client_read", "dcr.client_updated", "dcr.iat_issued",
		"dcr.iat_revoked",
	}},
	{"Tokens and consent", []AuditEventType{
		"oauth_authorize.code_issued", "oauth_authorize.error_redirect",
		"oauth_authorize.request_object_rejected",
		"oauth_consent.denied", "oauth_consent.granted",
		"oauth_token.issued", "oauth_token.revoked",
		"oidc_userinfo.served", "self_consent_revoked",
	}},
	{"Service accounts and agents", []AuditEventType{
		"agent_communication.token.issued", "agent_communication.token.refused",
		"agent_communication_authorization.created", "agent_communication_authorization.revoked",
		"service_account.created", "service_account.deleted", "service_account.disabled",
		"service_account.enabled", "service_account.linked_oauth_client",
		"service_account.owner_assigned", "service_account.unlinked_oauth_client",
		"service_account.updated", "service_account_client.created",
	}},
	{"Signing keys", []AuditEventType{
		"key.deprecated", "key.expired_purged", "key.generated", "key.rotated",
	}},
	{"Setup and instance", []AuditEventType{
		"claim.consumed", "claim.email_send_attempted", "claim.generated",
		"feature.denied", "instance.self_registration_updated", "setup.completed",
	}},
}

// auditLabelWords spells the abbreviations of the event names in plain words.
var auditLabelWords = map[string]string{
	"api": "API", "dcr": "dynamic registration", "iat": "initial access token",
	"mfa": "MFA", "oauth": "OAuth", "oidc": "OIDC", "org": "organization",
	"webauthn": "passkey",
}

// AuditEventTypeLabel is the one function that turns a recorded event name
// into its label: the name's words in order, separators as spaces, the first
// letter upper case ("user_session.login.mfa_verified" -> "User session
// login MFA verified").
func AuditEventTypeLabel(et AuditEventType) string {
	words := strings.FieldsFunc(string(et), func(r rune) bool { return r == '.' || r == '_' })
	for i, w := range words {
		if plain, ok := auditLabelWords[strings.ToLower(w)]; ok {
			words[i] = plain
		} else {
			words[i] = strings.ToLower(w)
		}
	}
	label := strings.Join(words, " ")
	if label == "" {
		return label
	}
	return strings.ToUpper(label[:1]) + label[1:]
}
