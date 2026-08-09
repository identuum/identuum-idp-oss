package service

import (
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// LocalCredentialFlowDecision is the result of IsLocalCredentialFlowAllowed.
// Allowed=true means the caller should proceed with the local credential
// check (password compare, MFA verify, webauthn ceremony, etc.).
// Allowed=false means the caller MUST reject without consulting any
// credential — and SHOULD do so with a wire shape indistinguishable from
// the generic invalid_credentials path (per §13.3 enumeration protection).
//
// SealReason is set to ErrLocalLoginDisabledForRole when the seal fires.
// It is for audit-event payloads and structured logs ONLY — handlers MUST
// NOT surface it on the wire.
type LocalCredentialFlowDecision struct {
	Allowed    bool
	SealReason error
}

// IsLocalCredentialFlowAllowed is the central policy function for per-org
// local-credential enforcement. Every route that requires a local Identuum
// credential (password login, LDAP, WebAuthn, MFA enrol/disable, password
// reset/change, email verification, invitation, self-registration) invokes
// this AFTER user resolution and BEFORE the credential check.
//
// Rule (per organization auth_policy — Decision D-001, D-004, D-005):
//
//   - orgAuthPolicy != AuthPolicyIDPOnly  → allowed (local credentials OK)
//   - orgAuthPolicy == AuthPolicyIDPOnly:
//   - role == RoleOrgUser    → DENIED (org's external IdP is the credential authority)
//   - role == RoleOrgAdmin   → allowed (admin local-only invariant — Decision D-004)
//   - role == RoleSiteAdmin  → allowed (admin local-only invariant — Decision D-004)
//   - any other role         → DENIED (fail-closed for unknown future roles)
//
// nil user is treated as fail-closed — a missing user should not reach
// this helper but the defensive default avoids accidentally allowing
// credential flows on routes that bypass user resolution.
//
// This function is pure (no I/O) so it is trivially unit-testable and can
// be invoked freely from any service layer.
func IsLocalCredentialFlowAllowed(user *domain.User, orgAuthPolicy string) LocalCredentialFlowDecision {
	if orgAuthPolicy != domain.AuthPolicyIDPOnly {
		return LocalCredentialFlowDecision{Allowed: true}
	}
	if user == nil {
		// Defence in depth — never seen in practice, but a missing user
		// should not silently grant access.
		return LocalCredentialFlowDecision{Allowed: false, SealReason: domain.ErrLocalLoginDisabledForRole}
	}
	switch user.Role {
	case domain.RoleSiteAdmin, domain.RoleOrgAdmin:
		return LocalCredentialFlowDecision{Allowed: true}
	case domain.RoleOrgUser:
		return LocalCredentialFlowDecision{Allowed: false, SealReason: domain.ErrLocalLoginDisabledForRole}
	default:
		// Unknown role — fail-closed so a future role transition that
		// forgets to update this switch defaults to "no credential
		// flow" rather than "free pass".
		return LocalCredentialFlowDecision{Allowed: false, SealReason: domain.ErrLocalLoginDisabledForRole}
	}
}
