package mw

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// failClosedGuard is the P-018 fail-closed fallback returned by an
// authorization-guard factory that was misconfigured at construction time
// (e.g. an empty route-param name). Previously such a factory panicked;
// now it records a fatal startup fault and returns THIS handler, which
// authorizes nothing — an unauthenticated request gets 401, any other
// request gets 403. It NEVER calls c.Next(), so a broken guard denies the
// protected route rather than admitting it.
func failClosedGuard(c *gin.Context) {
	if _, ok := PrincipalFromContext(c); !ok {
		respondUnauthenticated(c)
		return
	}
	respondForbidden(c)
}

// Org-scoped authorization gates. These guards compose with the
// existing role guards (RequireSiteAdmin / RequireScopesAny) to
// model the Identuum admin authority boundary at the HTTP layer:
//
//   - site_admin can act across tenants on the infrastructure-level
//     fields the monolith policy already permits.
//   - org_admin can act only inside their own organization.
//   - org_user (or unknown role) is rejected outright for these
//     gates — they are meant for tenant-level administration. Use
//     RequireAuthenticated alone (or RequireSelf) for self/profile
//     routes that any logged-in user may hit.
//
// None of these guards POPULATE the principal — they read what an
// upstream populator already attached (BearerPrincipal /
// InjectPrincipalForTest). No principal => 401. Malformed path
// param => 400. Role/org mismatch => 403.

// RequireSiteAdminOrSameOrgAdmin permits the request when the
// caller is a site_admin OR an org_admin whose Principal.OrganizationID
// equals the route's :paramName UUID. Use on tenant-level routes
// like /api/v1/organizations/:id/* where same-org org_admin access
// is policy-safe.
//
// Behavior:
//
//   - no principal           → 401
//   - malformed UUID param   → 400 (invalid path; treat as bad request,
//     not auth failure, so an org_admin can
//     distinguish a typo from a forbidden
//     cross-tenant probe)
//   - site_admin             → next
//   - org_admin, same org    → next
//   - org_admin, cross org   → 403
//   - other role / org_user  → 403
func RequireSiteAdminOrSameOrgAdmin(paramName string) gin.HandlerFunc {
	if paramName == "" {
		// P-018: an empty route-param name is a wiring error. Do not
		// panic — return the shared fail-closed guard so the protected
		// route is denied rather than crashing the process. (Minimal safe
		// conversion: paramName is a compile-time literal at every call
		// site, so this branch is unreachable in practice; no StartupReport
		// is threaded.)
		return failClosedGuard
	}
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		if !p.IsOrgAdminOnly() {
			respondForbidden(c)
			return
		}
		routeOrg, err := uuid.Parse(c.Param(paramName))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		if routeOrg == uuid.Nil || p.OrganizationID == uuid.Nil || routeOrg != p.OrganizationID {
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// RequireSiteAdminOrPrincipalOrg permits site_admin and any role
// whose Principal.OrganizationID is non-nil. Use for routes like
// GET /api/v1/organizations/current that derive the target org id
// from the principal itself rather than a path parameter.
//
// Behavior:
//
//   - no principal              → 401
//   - site_admin                → next (caller must still set the
//     organization id they want at the
//     handler layer; a site_admin with
//     no org id is the SystemActor case)
//   - any role with org id != Nil → next
//   - principal with org id == Nil → 400 (no org context; the route
//     cannot resolve a target tenant)
func RequireSiteAdminOrPrincipalOrg() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		if p.OrganizationID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		c.Next()
	}
}

// RequireSiteAdminOrSelf permits site_admin OR the principal whose
// UserID equals the route's :userIDParam UUID. Use on routes that
// expose self-management (e.g. /api/v1/users/:id/password where any
// logged-in user may rotate their own password but only site_admin
// may rotate someone else's).
//
// Behavior:
//
//   - no principal           → 401
//   - malformed UUID param   → 400
//   - site_admin             → next
//   - principal.UserID == :id → next
//   - everyone else          → 403
func RequireSiteAdminOrSelf(report *lifecycle.StartupReport, userIDParam string) gin.HandlerFunc {
	if userIDParam == "" {
		// P-018: a guard with no route-param name cannot evaluate access.
		// Record a fatal fault and fail closed instead of panicking.
		report.Fatal(
			"authz-guard:require-self",
			"authorization guard misconfigured: RequireSiteAdminOrSelf received an empty userIDParam",
		)
		return failClosedGuard
	}
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		routeUser, err := uuid.Parse(c.Param(userIDParam))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}
		if routeUser == uuid.Nil || p.UserID == uuid.Nil || routeUser != p.UserID {
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// ============================================================
// Composed role + scope guards.
//
// The plain RequireSiteAdmin* helpers above check role only. The
// monolith's HTTP guard for tenant-level routes is
// `RequireScopesAny(scope1, scope2, ...)` — scope-aware but
// role-agnostic. These composed helpers combine BOTH so an
// org_admin needs same-org membership AND the required scope to
// pass. site_admin bypasses the scope check (Identuum policy:
// site_admin carries the platform's full authority and the OSS
// shape does not yet pin a scope set on site_admin tokens).
//
// All three helpers follow the same precedence order:
//
//   1. no principal              → 401
//   2. site_admin                → next (bypasses scope check)
//   3. malformed UUID param      → 400  (only for same-org / self variants)
//   4. role + org/self check     → next or 403
//   5. scope check               → next or 403
//
// Reasoning: returning 400 for a malformed path UUID before the
// scope check matches the unscoped guards' shape so callers can
// distinguish a typo from a forbidden cross-tenant probe. Scope
// failures and role failures both surface as 403 — the response
// body deliberately does not say which.
// ============================================================

// principalHasAnyScope returns true if p.Scope contains at least
// one of needed (OAuth whitespace-separated). Empty needed → true.
func principalHasAnyScope(p *domain.Principal, needed []string) bool {
	if len(needed) == 0 {
		return true
	}
	if p == nil || p.Scope == "" {
		return false
	}
	held := make(map[string]struct{}, 8)
	for _, s := range strings.Fields(p.Scope) {
		held[s] = struct{}{}
	}
	for _, n := range needed {
		if _, ok := held[n]; ok {
			return true
		}
	}
	return false
}

// RequireSiteAdminOrSameOrgAdminWithScopes mirrors
// RequireSiteAdminOrSameOrgAdmin but additionally requires the
// org_admin actor to hold at least one of scopes. site_admin
// bypasses the scope check.
func RequireSiteAdminOrSameOrgAdminWithScopes(report *lifecycle.StartupReport, orgParam string, scopes ...string) gin.HandlerFunc {
	if orgParam == "" {
		// P-018: see failClosedGuard — fatal fault + fail closed, no panic.
		report.Fatal(
			"authz-guard:org-admin-scopes",
			"authorization guard misconfigured: RequireSiteAdminOrSameOrgAdminWithScopes received an empty orgParam",
		)
		return failClosedGuard
	}
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		if !p.IsOrgAdminOnly() {
			respondForbidden(c)
			return
		}
		routeOrg, err := uuid.Parse(c.Param(orgParam))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		if routeOrg == uuid.Nil || p.OrganizationID == uuid.Nil || routeOrg != p.OrganizationID {
			respondForbidden(c)
			return
		}
		if !principalHasAnyScope(p, scopes) {
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// RequireSiteAdminOrOrgAdminWithScopes permits site_admin and
// org_admin actors WITHOUT consulting a path :orgID parameter.
// Use on routes that do not carry an org id in the URL (e.g.
// GET /api/v1/users — the tenant scope is the org_admin's home
// org, derived from Principal.OrganizationID at the service
// layer). org_admin still needs the scope.
//
// Behavior:
//
//   - no principal           → 401
//   - site_admin             → next (scope bypass)
//   - org_admin with scope   → next
//   - org_admin missing scope → 403
//   - any other role         → 403
func RequireSiteAdminOrOrgAdminWithScopes(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		if !p.IsOrgAdminOnly() {
			respondForbidden(c)
			return
		}
		if p.OrganizationID == uuid.Nil {
			respondForbidden(c)
			return
		}
		if !principalHasAnyScope(p, scopes) {
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// RequireSiteAdminOrSelfOrSameOrgAdminWithScopes permits:
//
//   - site_admin (scope bypass)
//   - the principal whose UserID == :userParam
//   - org_admin whose OrganizationID == :orgParam AND who holds
//     one of the supplied scopes
//
// Use on routes that need the same-org tenant gate AND a self
// fallback. Example: a PUT that an end-user can hit for their
// own row even without admin scope.
//
// If orgParam is empty, the same-org branch is skipped (acts as
// site_admin-OR-self only). If userParam is empty, the self
// branch is skipped.
func RequireSiteAdminOrSelfOrSameOrgAdminWithScopes(orgParam, userParam string, scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if p.IsSiteAdmin() {
			c.Next()
			return
		}
		// Self branch.
		if userParam != "" {
			routeUser, err := uuid.Parse(c.Param(userParam))
			if err == nil && routeUser != uuid.Nil && p.UserID != uuid.Nil && routeUser == p.UserID {
				c.Next()
				return
			}
		}
		// org_admin same-org branch.
		if orgParam != "" && p.IsOrgAdminOnly() {
			routeOrg, err := uuid.Parse(c.Param(orgParam))
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
				return
			}
			if routeOrg != uuid.Nil && p.OrganizationID != uuid.Nil && routeOrg == p.OrganizationID && principalHasAnyScope(p, scopes) {
				c.Next()
				return
			}
		}
		respondForbidden(c)
	}
}
