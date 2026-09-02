package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// IntrospectionHandlerDeps wires the OSS RFC 7662 introspection
// endpoint.
//
// IntrospectionService is required. Audit defaults to NoopService.
// ClientAuth, when non-nil, is mounted in front of the route per
// RFC 7662 §2.1 ("The introspection endpoint MUST be protected by
// a transport-layer security mechanism..."). When nil, the route
// falls back to RequireSiteAdmin so an OSS deployment that wires
// only a bearer-token verifier still gets a protected route.
type IntrospectionHandlerDeps struct {
	IntrospectionService *service.IntrospectionService
	Audit                audit.Service
	ClientAuth           mw.OAuthClientAuthenticator

	// StartupReport threads the P-018 fault accumulator into the OAuth
	// client-auth guard factory. Nil-safe.
	StartupReport *lifecycle.StartupReport

	// Limiter, when non-nil, is a per-client rate-limit middleware
	// (built by the router from RateLimitConfig.IntrospectionLimit)
	// applied AFTER client authentication, so it keys on the
	// authenticated client. Nil (zero-value deps / tests) is a noop.
	Limiter gin.HandlerFunc

	// PreAuthLimiter (CONF-9), when non-nil, mounts BEFORE the OAuth client
	// auth guard and therefore sees UNAUTHENTICATED traffic. It must be
	// IP-keyed: pre-auth there is no client to key on. Without it, the guard
	// aborts a wrong client_secret before the per-client Limiter below ever
	// runs, so secret-grinding is met by bcrypt at full speed and never a 429.
	// The post-auth Limiter stays: post-auth IP keying would collapse NAT'd
	// clients into one bucket. /revoke has had limiter-first since CONF-7;
	// this brings the other two client-auth routes level. Nil is a noop.
	PreAuthLimiter gin.HandlerFunc
}

// RegisterIntrospectionRoutes mounts
//
//	POST /api/v1/oauth/introspection
//
// onto router. The monolith mounts the equivalent endpoint at
// /api/v1/auth/introspect; OSS deliberately publishes the path
// suggested by RFC 7662 §2.1 ("introspection_endpoint") so a
// CE composition can advertise either or both in its OIDC
// discovery document.
//
// Authorization:
//
//   - When deps.ClientAuth is non-nil, the route mounts
//     mw.RequireOAuthClient(deps.ClientAuth) — canonical RFC
//     7662 §2.1 client_secret_basic / client_secret_post
//     authentication. This is the production-shaped path.
//   - When deps.ClientAuth is nil, the route falls back to
//     mw.RequireSiteAdmin() so an OSS deployment that has not
//     yet wired client auth still gets a protected route.
//
// The audit hook is not consumed in this slice. Successful
// introspection is a high-volume read path; the monolith does
// not emit audit on introspection success either.
func RegisterIntrospectionRoutes(router gin.IRouter, deps IntrospectionHandlerDeps) {
	if deps.IntrospectionService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/oauth")
	// CONF-9: the pre-auth, IP-keyed limiter mounts FIRST so an
	// unauthenticated flood is throttled instead of riding straight into
	// the auth stack. See the PreAuthLimiter field doc.
	if deps.PreAuthLimiter != nil {
		g.Use(deps.PreAuthLimiter)
	}
	if deps.ClientAuth != nil {
		g.Use(mw.RequireOAuthClient(deps.StartupReport, deps.ClientAuth))
	} else {
		g.Use(mw.RequireSiteAdmin())
	}
	// Per-client rate limit runs AFTER the auth guard so it keys on the
	// authenticated client. Nil-safe (noop when unconfigured).
	if deps.Limiter != nil {
		g.Use(deps.Limiter)
	}

	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/introspection
	// docgen:summary=RFC 7662 token introspection (returns {"active":false} for revoked or unknown tokens).
	// docgen:tier=oss
	// docgen:auth=oauth_client
	// docgen:notes=Falls back to site_admin auth when ClientAuth is not wired (e.g. legacy operator paths).
	g.POST("/introspection", HandleIntrospection(deps))
}

// HandleIntrospection implements the introspection logic.
//
// Request shape (RFC 7662 §2.1 + JSON-body extension):
//
//   - application/x-www-form-urlencoded:  token=<jwt>
//   - application/json:                   {"token":"<jwt>"}
//
// The token_type_hint parameter is read but ignored — the OSS
// verifier accepts only signed JWTs (no opaque-reference tokens
// yet), so the hint adds no behavior.
//
// Response shape (RFC 7662 §2.2 + monolith-parity fields):
//
//	{
//	  "active":     bool,
//	  "scope":      string,
//	  "client_id":  string,
//	  "username":   string,
//	  "token_type": "Bearer",
//	  "exp":        int64,
//	  "iat":        int64,
//	  "nbf":        int64,
//	  "sub":        string,
//	  "aud":        [string],
//	  "iss":        string,
//	  "jti":        string
//	}
//
// Behavior:
//
//   - Empty token         → 400 {"error":"invalid_request"}
//   - Verifier failure    → 200 {"active":false}
//   - Verified token      → 200 {"active":true, ...claims}
//
// The raw token is NEVER echoed in the response body.
func HandleIntrospection(deps IntrospectionHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := readIntrospectionToken(c)
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		resp, storeErr := deps.IntrospectionService.IntrospectVerdict(c.Request.Context(), token)
		if storeErr != nil {
			// AUTH-503: the key / revocation STORE erred — RFC 7662's
			// {"active":false} is a VERDICT the OP has not reached; answer 503
			// with an ERROR log so the RP retries instead of treating a live
			// token as inactive.
			mw.RespondAuthStoreUnavailable(c, "introspection", storeErr)
			return
		}
		c.JSON(http.StatusOK, resp)
	}
}

// readIntrospectionToken extracts the token string from either an
// x-www-form-urlencoded body or a JSON body. The form path is the
// RFC 7662 canonical shape; the JSON path is a small ergonomic
// extension for operators using cURL with --data-urlencode-less
// invocations.
func readIntrospectionToken(c *gin.Context) string {
	contentType := c.GetHeader("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		var body struct {
			Token string `json:"token"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			return strings.TrimSpace(body.Token)
		}
		return ""
	}
	// Default: x-www-form-urlencoded (RFC 7662 canonical).
	return strings.TrimSpace(c.PostForm("token"))
}
