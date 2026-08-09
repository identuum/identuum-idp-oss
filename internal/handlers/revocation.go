package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RevocationHandlerDeps wires the OSS RFC 7009-style revocation
// endpoint.
//
// IntrospectionService is required (the verifier reuse path —
// revocation reuses the same token verification chain so we know
// which user_id to revoke against).
// SessionRevoker, when non-nil, is the fan-out hook invoked when
// a successfully-verified token resolves to a UserID; when nil it
// is replaced with service.NoopSessionRevoker so the route
// remains safely callable in deployments that have not yet wired
// a real session store.
// TokenRevocationService, when non-nil, persists a per-jti
// revocation row so subsequent /api/v1/oauth/introspection calls
// flip the same token to `{"active":false}`. When nil, the route
// still runs (RFC 7009 §2.2 wire shape unchanged) but no
// jti-based revocation lands — the OSS deployment is then
// effectively session-revoke-only, matching pre-this-slice
// behavior.
// ClientAuth, when non-nil, mounts the canonical RFC 7009 §2.1
// client-auth in front of the route. When nil, the route falls
// back to RequireSiteAdmin (same fallback contract as
// introspection).
// Audit defaults to NoopService.
type RevocationHandlerDeps struct {
	IntrospectionService   *service.IntrospectionService
	SessionRevoker         service.SessionRevoker
	TokenRevocationService *service.TokenRevocationService
	RefreshTokenService    *service.RefreshTokenService
	ClientAuth             mw.OAuthClientAuthenticator
	Audit                  audit.Service

	// StartupReport threads the P-018 fault accumulator into the OAuth
	// client-auth guard factory. Nil-safe.
	StartupReport *lifecycle.StartupReport

	// Limiter, when non-nil, is the rate-limit middleware for this route.
	// It is mounted BEFORE the client-auth guard — see RegisterRevocationRoutes
	// for why that ordering is the whole point. Nil-safe (no limit when unset).
	Limiter gin.HandlerFunc
}

// RegisterRevocationRoutes mounts
//
//	POST /api/v1/oauth/revoke
//
// onto router. RFC 7009 §2.2 mandates that the revocation
// endpoint return 200 (no body required) regardless of whether
// the supplied token was valid. OSS follows that — invalid /
// expired / malformed tokens silently succeed.
//
// The route registers ONLY when IntrospectionService is non-nil
// (no verifier → no way to extract the user_id to revoke for).
//
// Authorization mirrors the introspection route's contract.
func RegisterRevocationRoutes(router gin.IRouter, deps RevocationHandlerDeps) {
	if deps.IntrospectionService == nil {
		return
	}
	if deps.SessionRevoker == nil {
		deps.SessionRevoker = service.NoopSessionRevoker{}
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/oauth")
	// The rate limit runs BEFORE the auth guard, DELIBERATELY, and this is the
	// one place in the OAuth surface that does so.
	//
	// mw.RequireOAuthClient aborts on every authentication failure
	// (respondInvalidClient; return), so a limiter mounted after it — the shape
	// /token and /introspection use — never runs for a request whose credential
	// was wrong. That leaves an unthrottled guess-and-check oracle against
	// client_secret: wrong secrets simply 401 forever, at any rate.
	//
	// The cost of mounting first, stated honestly: the bucket is PER IP and
	// never per client, because oauthClientRateLimitKey has nobody to key on
	// until the guard has run. A busy legitimate caller sharing one egress IP
	// can therefore be throttled where it previously could not, and it cannot
	// be exempted per-client the way /token can. That is accepted here — an
	// unbounded client_secret oracle is the worse risk, and pre-auth there is
	// nothing else to key on. The fallback is per-IP, not a single shared
	// bucket (internal/mw/rate_limit.go), so one caller cannot starve all.
	if deps.Limiter != nil {
		g.Use(deps.Limiter)
	}
	if deps.ClientAuth != nil {
		g.Use(mw.RequireOAuthClient(deps.StartupReport, deps.ClientAuth))
	} else {
		g.Use(mw.RequireSiteAdmin())
	}

	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/revoke
	// docgen:summary=RFC 7009 token revocation (idempotent — unknown tokens return 200 per spec).
	// docgen:tier=oss
	// docgen:auth=oauth_client
	// docgen:notes=Falls back to site_admin auth when ClientAuth is not wired.
	g.POST("/revoke", HandleRevoke(deps))
}

// HandleRevoke implements RFC 7009 revocation behavior subject to
// the OSS constraints:
//
//   - Missing token → 400 {"error":"invalid_request"} per RFC
//     7009 §2.2.1 + RFC 6749 §5.2.
//   - Token present (valid or invalid) → 200 with empty body.
//     RFC 7009 §2.2 explicitly forbids leaking the existence of
//     the token through differential responses.
//   - On successful verification, if the token carries a UserID
//     claim the SessionRevoker is invoked with reason
//     "oauth_token_revoked" and safe metadata `{client_id}`.
//   - SessionRevoker errors are best-effort (swallowed — a
//     session-revoke failure does not block the JTI write).
//   - A genuine store I/O error from RevokeByRawToken or
//     RevokeJTI returns 500 (R8). RFC 7009 §2.2's unconditional
//     200 applies only to invalid/not-found/already-revoked
//     tokens, not to infrastructure failures.
//
// The raw token, raw client secret, and any verifier failure
// detail are NEVER echoed in the response body.
func HandleRevoke(deps RevocationHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := readRevocationToken(c)
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		hint := strings.ToLower(strings.TrimSpace(c.PostForm("token_type_hint")))
		// RFC 7009 §2.1 — token_type_hint is advisory; we attempt
		// the hinted lookup first when present, otherwise we try
		// refresh-token first (the selector.validator format is
		// fast-fail on a JWT shape) then fall back to access-token
		// introspection. The wire response is the same 200 either
		// way.
		safeMeta := map[string]any{}
		if ac, ok := mw.AuthenticatedClientFromContext(c); ok && ac != nil {
			safeMeta["client_id"] = ac.ClientID
			safeMeta["client_kind"] = string(ac.Kind)
		}
		if hint == "refresh_token" || hint == "" {
			revoked, storeErr := tryRevokeRefreshToken(c, deps, token, safeMeta)
			if storeErr != nil {
				// R8: genuine store I/O error — not a token-validity issue.
				c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
				return
			}
			if revoked {
				c.JSON(http.StatusOK, gin.H{})
				return
			}
		}
		// Reuse the IntrospectionService — its safe response carries
		// `active`, `sub`, `jti`, `exp`. We do NOT serialize the
		// response back to the caller; we only use it for the
		// revoker fan-out and the jti-based persistence.
		resp := deps.IntrospectionService.Introspect(c.Request.Context(), token)
		if resp.Active {
			meta := map[string]any{}
			if ac, ok := mw.AuthenticatedClientFromContext(c); ok && ac != nil {
				meta["client_id"] = ac.ClientID
				meta["client_kind"] = string(ac.Kind)
			}
			var (
				firedSession bool
				firedJTI     bool
			)
			// Session-revoker fan-out: only when the token's sub is a
			// UUID (i.e. a human user). client_credentials tokens
			// carry the client_id in sub and never produce sessions.
			//
			// RFC 7009 §2.1 client-binding (R4): an authenticated OAuth
			// client may fan out the subject's session revocation ONLY for
			// a token it owns — otherwise one client could log a user out
			// of every session via a token issued to a different client.
			// The site_admin authority path (no OAuth client) keeps the
			// broad revoke; an indeterminate token client fails closed.
			if resp.Sub != "" && sessionFanoutAllowed(c, resp.ClientID) {
				if uid, err := uuid.Parse(resp.Sub); err == nil && uid != uuid.Nil {
					_ = deps.SessionRevoker.RevokeUserSessions(
						c.Request.Context(),
						uid,
						"oauth_token_revoked",
						meta,
					)
					firedSession = true
				}
			}
			// jti-based persistence: every verified token with a jti
			// AND an exp lands a row so /introspection flips it to
			// active:false going forward. Includes client_credentials
			// tokens (whose sub is the client_id, not a UUID).
			if deps.TokenRevocationService != nil && resp.Jti != "" && resp.Exp > 0 {
				expAt := time.Unix(resp.Exp, 0).UTC()
				if err := deps.TokenRevocationService.RevokeJTI(
					c.Request.Context(),
					resp.Jti,
					expAt,
					"oauth_token_revoked",
					meta,
				); err != nil {
					// R8: distinguish sentinel input-validation errors
					// (won't fire here given resp.Jti!="" and resp.Exp>0
					// guards above, but checked as a safety belt) from
					// genuine store I/O errors.
					if !errors.Is(err, service.ErrTokenRevocationInvalidJTI) &&
						!errors.Is(err, service.ErrTokenRevocationInvalidExpiry) {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
						return
					}
					// Sentinel: treat as skip (token already expired or
					// invalid arg). RFC 7009 §2.2 still returns 200.
				} else {
					firedJTI = true
				}
			}
			if firedSession || firedJTI {
				_ = deps.Audit.Record(c.Request.Context(), audit.Event{
					Action:    string(domain.AuditOAuthTokenRevoked),
					Outcome:   "success",
					IPAddress: c.ClientIP(),
					UserAgent: c.Request.UserAgent(),
					Metadata:  meta,
				})
			}
		}
		// RFC 7009 §2.2 — 200 with no body required. We send an
		// empty JSON object so curl-like clients get a parseable
		// response.
		c.JSON(http.StatusOK, gin.H{})
	}
}

// authenticatedOAuthClientID returns the authenticated OAuth client's ID,
// or "" when the caller is not an authenticated OAuth client. The R4
// client-binding gates key off this: "" is the site_admin authority
// fallback path (RequireSiteAdmin sets a principal but NO OAuth client),
// under which the broad revoke is preserved; a non-empty value gates the
// caller to revoking only tokens it owns.
func authenticatedOAuthClientID(c *gin.Context) string {
	if ac, ok := mw.AuthenticatedClientFromContext(c); ok && ac != nil {
		return ac.ClientID
	}
	return ""
}

// sessionFanoutAllowed decides whether the access-token /revoke path may
// fan out a full-session revocation for the introspected subject (R4).
// The site_admin authority path (no authenticated OAuth client ⇒ "")
// retains the broad revoke. An authenticated OAuth client may fan out
// ONLY for a token it owns; an indeterminate token client (empty
// tokenClientID) fails closed — no cross-client fan-out.
func sessionFanoutAllowed(c *gin.Context, tokenClientID string) bool {
	authedClientID := authenticatedOAuthClientID(c)
	if authedClientID == "" {
		return true // site_admin authority path — unchanged
	}
	return tokenClientID != "" && tokenClientID == authedClientID
}

// tryRevokeRefreshToken attempts to interpret `token` as a
// selector.validator refresh token and revoke it.
//
// Return semantics (R8):
//   - (true,  nil) — row successfully revoked, OR cross-client
//     OwnerMismatch (silent 200 per R4); caller short-circuits.
//   - (false, nil) — token not recognised / not found / validator
//     mismatch; caller falls through to the access-token path.
//   - (false, err) — genuine store I/O error from RevokeByRawToken;
//     caller returns 500.
//
// On a refresh-token hit AND when the row carried an AccessJTI,
// the JTI cascade write is best-effort (errors swallowed): the
// primary revocation already succeeded and the JTI row is an
// optimisation for introspection.
func tryRevokeRefreshToken(c *gin.Context, deps RevocationHandlerDeps, token string, meta map[string]any) (bool, error) {
	if deps.RefreshTokenService == nil {
		return false, nil
	}
	// RFC 7009 §2.1 client-binding (R4): pass the authenticated OAuth
	// client (or "" for the site_admin authority path) so the row is
	// revoked ONLY when the caller owns it.
	result, err := deps.RefreshTokenService.RevokeByRawToken(c.Request.Context(), token, authenticatedOAuthClientID(c))
	if err != nil {
		// R8: genuine store I/O error — surface to caller.
		return false, err
	}
	if result == nil || !result.Found {
		// Token not present in refresh-token store; fall through to
		// the access-token introspection path.
		return false, nil
	}
	// Cross-client caller: the token was recognized but deliberately NOT
	// revoked (it belongs to another client). Return a silent idempotent
	// 200 — no JTI cascade, no "revoked" audit; the token stays valid. The
	// wire response is indistinguishable from a real revoke (no oracle).
	if result.OwnerMismatch {
		return true, nil
	}
	if result.AccessJTI != "" && deps.TokenRevocationService != nil {
		// Best-effort JTI cascade: the primary MarkRevoked already
		// succeeded above; we don't know the exact exp so use a
		// conservative 1h horizon matching the default access TTL.
		expAt := time.Now().UTC().Add(time.Hour)
		_ = deps.TokenRevocationService.RevokeJTI(
			c.Request.Context(),
			result.AccessJTI,
			expAt,
			"oauth_refresh_revoked",
			meta,
		)
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    string(domain.AuditOAuthTokenRevoked),
		Outcome:   "success",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata: mergeAuditMeta(meta, map[string]any{
			"token_kind": "refresh_token",
		}),
	})
	return true, nil
}

// mergeAuditMeta returns a shallow union of base + extra. Keys
// in extra win on collision.
func mergeAuditMeta(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// readRevocationToken extracts the token parameter from form or
// JSON body, mirroring the introspection handler's dual-shape
// support. Whitespace-only tokens are treated as empty.
func readRevocationToken(c *gin.Context) string {
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
	return strings.TrimSpace(c.PostForm("token"))
}
