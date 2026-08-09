package mw

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/features"
)

// RequireFeature returns a Gin middleware that allows the request
// through only when gate.IsFeatureEnabled(feature, roles...)
// returns true.
//
// Policy decisions:
//
//   - A nil gate defaults to features.OpenGate. Documented as the
//     OSS default for Phase 2: the open-core split must not regress
//     route reachability before CE composition installs a
//     tier-aware gate. Operators that need fail-closed behavior
//     wire features.ClosedGate or a constructed features.StaticGate
//     in OSSRouterDeps.FeatureGate.
//   - A denied feature returns 403 with a JSON body of
//     {"error":"feature not enabled","feature":"<name>"}. The
//     feature name is echoed so an operator inspecting a 403
//     response can identify which gate denied it; the gate
//     implementation itself is never echoed. No tokens, scopes,
//     license payload, hashes, or audit metadata leak through this
//     path.
//   - Roles, when supplied, are forwarded verbatim to the gate.
//     This preserves the existing
//     (*license.Service).IsFeatureEnabled signature semantics so a
//     gate that special-cases site_admin (e.g. the OSS
//     StarterFeatureGate's MFA invariant) behaves identically.
//
// The middleware is intentionally stateless and dependency-light;
// no DB, no network, no logger.
func RequireFeature(gate features.FeatureGate, feature string, roles ...string) gin.HandlerFunc {
	if gate == nil {
		gate = features.OpenGate{}
	}
	return func(c *gin.Context) {
		if !gate.IsFeatureEnabled(feature, roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "feature not enabled",
				"feature": feature,
			})
			return
		}
		c.Next()
	}
}

// RequireFeatureWithAudit is the audit-aware variant of
// RequireFeature. Behavior is identical except that a denial also
// emits one `audit.Event` through the supplied audit.Service with
// action "feature.denied".
//
// Audit metadata carried on the denial event is deliberately
// minimal and safe:
//
//   - feature: the gated feature name
//   - method:  the HTTP method
//   - path:    the request URL path (no query string)
//   - actor_role: the principal's role string when populated;
//     empty for unauthenticated callers. The principal's email,
//     scope claims, organization id, user id, session id, and
//     bearer token are NEVER included.
//
// An audit emission error is intentionally swallowed: the client
// still receives the 403, and the failure does not leak through
// the response body. nil audit defaults to a no-op so wiring the
// audit-aware variant is always safe.
//
// nil gate defaults to features.OpenGate{} (documented OSS default).
func RequireFeatureWithAudit(gate features.FeatureGate, auditSvc audit.Service, feature string, roles ...string) gin.HandlerFunc {
	if gate == nil {
		gate = features.OpenGate{}
	}
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	return func(c *gin.Context) {
		if !gate.IsFeatureEnabled(feature, roles...) {
			meta := map[string]any{
				"feature": feature,
				"method":  c.Request.Method,
				"path":    c.Request.URL.Path,
			}
			if p, ok := PrincipalFromContext(c); ok && p != nil {
				meta["actor_role"] = string(p.Role)
			}
			_ = auditSvc.Record(c.Request.Context(), audit.Event{
				Action:    "feature.denied",
				Outcome:   "denied",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				Metadata:  meta,
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "feature not enabled",
				"feature": feature,
			})
			return
		}
		c.Next()
	}
}
