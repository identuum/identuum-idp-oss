package domain

import "github.com/google/uuid"

// Principal represents the authenticated entity (user or client) in the domain layer.
// It decouples the service layer from transport-specific JWT tokens.
type Principal struct {
	Email    string
	Role     UserRole
	Scope    string
	ClientID string
	// TokenID is the JWT `jti` claim — the per-token identifier RFC 7009
	// revocation keys on. Retained so the bearer path can reject a revoked
	// token for EVERY principal, not only session-bearing ones (P0-6).
	TokenID string
	// Sub is the JWT `sub` claim VERBATIM — the exact string the token
	// carried, whatever its shape.
	//
	// Distinct from UserID on purpose, and not redundant with it. UserID is a
	// uuid: it is uuid.Nil when `sub` is not a uuid, and it is OVERWRITTEN by
	// a `user_id` claim when one is present, so it can differ from `sub`
	// outright. Anything contractually defined as "the sub claim" must read
	// this field — notably pkg/oidc.PrincipalRef.Subject, whose doc says
	// verbatim (CONF-11). Anything keying an internal uuid lookup wants
	// UserID.
	Sub            string
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	SessionID      uuid.UUID
}

// IsSiteAdmin checks if the principal has site-wide admin privileges
func (p *Principal) IsSiteAdmin() bool {
	return p.Role == RoleSiteAdmin
}

// IsOrgAdmin returns true for both RoleOrgAdmin and RoleSiteAdmin.
//
// Intended use: login-path checks where both administrative roles are treated
// equivalently (e.g. idp_only policy bypass for admin lockout prevention).
// The name "IsOrgAdmin" is retained for backward compatibility.
//
// WARNING: Do not use this method as a tenant resource-management authorization gate.
// Phase 8.d guards (guardSiteAdminTenant*) enforce the correct boundary.
// For a check that returns true ONLY for RoleOrgAdmin, use IsOrgAdminOnly().
func (p *Principal) IsOrgAdmin() bool {
	return p.Role == RoleOrgAdmin || p.Role == RoleSiteAdmin
}

// IsOrgAdminOnly returns true if and only if the principal has exactly RoleOrgAdmin.
// Unlike IsOrgAdmin(), this returns false for RoleSiteAdmin.
// Use this helper when checking for org_admin authority in authorization gates
// where site_admin must not be granted the same access.
func (p *Principal) IsOrgAdminOnly() bool {
	return p.Role == RoleOrgAdmin
}

// SystemActor returns a synthetic Principal for internal/automated operations that
// have no human actor. Audit events produced with this actor carry a recognisable
// system identity in their ActorID field rather than a nil UUID.
func SystemActor() *Principal {
	return &Principal{
		Role:           RoleSiteAdmin,
		OrganizationID: uuid.MustParse(SystemOrgID),
	}
}
