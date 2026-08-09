package mw

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// Audit-aware scope guards.
//
// These are drop-in variants of the existing org-scope guards
// (RequireSiteAdminOrSameOrgAdminWithScopes /
// RequireSiteAdminOrOrgAdminWithScopes) plus a stand-alone
// RequireScopesAnyWithAudit. Each one mirrors its non-audit
// sibling's authorization decision exactly; the only change is
// that a denial caused by missing scopes (or, for the composed
// guards, missing scopes AND the role/tenant predicate already
// passed) additionally records one `audit.Event` with action
// "scope.denied".
//
// Metadata carried on the denial event is deliberately minimal
// and safe:
//
//   - required_scopes: the slice of scope strings the route demands
//   - method:          the HTTP method
//   - path:            the URL path (no query string)
//   - actor_role:      principal's role string when populated;
//                      empty for unauthenticated callers
//
// The principal's email, full scope claim, organization id, user
// id, session id, client_id, bearer token, MFA secret, password,
// and license payload are NEVER included. The audit emission
// error is intentionally swallowed: the client still receives the
// generic 403, and the failure does not leak through the
// response body.
//
// Why the metadata excludes the principal's *held* scopes:
// the held-scope string can carry tenant identifiers and
// client-internal flags that should not enter the audit ledger.
// Only the route-supplied required-scopes are emitted because
// those are operator-defined and safe by construction.
//
// nil audit defaults to audit.NoopService{} so wiring the
// audit-aware variant is always safe.

// emitScopeDenial records the "scope.denied" event. Internal
// helper shared by the three audit-aware guards.
func emitScopeDenial(c *gin.Context, auditSvc audit.Service, required []string) {
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	meta := map[string]any{
		"required_scopes": append([]string(nil), required...),
		"method":          c.Request.Method,
		"path":            c.Request.URL.Path,
	}
	if p, ok := PrincipalFromContext(c); ok && p != nil {
		meta["actor_role"] = string(p.Role)
	}
	_ = auditSvc.Record(c.Request.Context(), audit.Event{
		Action:    "scope.denied",
		Outcome:   "denied",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata:  meta,
	})
}

// RequireScopesAnyWithAudit is the audit-aware variant of
// RequireScopesAny. Behavior matrix is identical (no principal →
// 401; principal with no overlap → 403; principal with overlap →
// next; empty scopes argument → next pass-through), and a 403
// caused by missing scopes additionally emits one
// "scope.denied" audit event.
func RequireScopesAnyWithAudit(auditSvc audit.Service, scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(scopes) == 0 {
			c.Next()
			return
		}
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		held := make(map[string]struct{}, 8)
		for _, s := range strings.Fields(p.Scope) {
			held[s] = struct{}{}
		}
		for _, need := range scopes {
			if _, ok := held[need]; ok {
				c.Next()
				return
			}
		}
		emitScopeDenial(c, auditSvc, scopes)
		respondForbidden(c)
	}
}

// RequireSiteAdminOrSameOrgAdminWithScopesAudit is the
// audit-aware variant of RequireSiteAdminOrSameOrgAdminWithScopes.
// Authorization decision matches exactly; a 403 caused by a
// scope failure (the role + same-org predicate already passed)
// additionally emits "scope.denied".
//
// 401, 400, and role/cross-org 403s do NOT emit scope.denied —
// those are not scope failures.
func RequireSiteAdminOrSameOrgAdminWithScopesAudit(report *lifecycle.StartupReport, auditSvc audit.Service, orgParam string, scopes ...string) gin.HandlerFunc {
	if orgParam == "" {
		// P-018: see failClosedGuard — fatal fault + fail closed, no panic.
		report.Fatal(
			"authz-guard:org-admin-scopes-audit",
			"authorization guard misconfigured: RequireSiteAdminOrSameOrgAdminWithScopesAudit received an empty orgParam",
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
			emitScopeDenial(c, auditSvc, scopes)
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// RequireSiteAdminOrOrgAdminWithScopesAudit is the audit-aware
// variant of RequireSiteAdminOrOrgAdminWithScopes. A 403 caused
// by a scope failure (the org_admin role + non-nil org id
// predicate already passed) emits "scope.denied"; role/nil-org
// 403s do not.
func RequireSiteAdminOrOrgAdminWithScopesAudit(auditSvc audit.Service, scopes ...string) gin.HandlerFunc {
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
			emitScopeDenial(c, auditSvc, scopes)
			respondForbidden(c)
			return
		}
		c.Next()
	}
}
