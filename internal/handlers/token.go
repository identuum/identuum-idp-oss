package handlers

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// SessionByIDLookup is the narrow seam the authorization_code
// grant consumes to resolve a session_id → *domain.Session so the
// user-token issuer can stamp acr / auth_time / amr claims.
// *PgxSessionRepository satisfies it via GetByID.
type SessionByIDLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
}

// OrganizationByIDLookup is the narrow seam the authorization_code
// grant consumes to resolve organization_id → *domain.Organization so
// the exchange can refuse a code whose tenant has since been suspended
// (Active=false) or deleted (DeletedAt set). *PgxOrganizationRepository
// satisfies it via GetByID.
type OrganizationByIDLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// TokenHandlerDeps wires the OSS RFC 6749 §4.4 client_credentials
// token endpoint.
//
// TokenService is required. ClientAuth is required (the endpoint
// MUST authenticate the calling client; no site_admin fallback
// is offered for this path because token issuance to a bearer
// principal is a category error). Audit defaults to NoopService.
type TokenHandlerDeps struct {
	TokenService *service.TokenService
	ClientAuth   mw.OAuthClientAuthenticator
	Audit        audit.Service

	// StartupReport threads the P-018 fault accumulator into the OAuth
	// client-auth guard factory. Nil-safe.
	StartupReport *lifecycle.StartupReport

	// Limiter, when non-nil, is a per-client rate-limit middleware
	// (built by the router from RateLimitConfig.TokenLimit) applied to
	// the token route AFTER client authentication, so it keys on the
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

	// AuthCodeService, UserToken, UserLookup, SessionLookup, and
	// OrgLookup together enable the authorization_code grant on the
	// token endpoint. All five must be wired for the grant to register
	// — when any is nil the handler returns unsupported_grant_type for
	// grant_type=authorization_code, preserving the legacy
	// "client_credentials and refresh_token only" posture. OrgLookup is
	// REQUIRED (not optional) so the exchange-time tenant-liveness
	// recheck can never be silently skipped: a missing OrgLookup fails
	// closed by disabling the grant, never by minting a token without
	// the org check.
	AuthCodeService *service.AuthorizationCodeService
	UserToken       *service.UserTokenService
	UserLookup      UserByIDLookup
	SessionLookup   SessionByIDLookup
	OrgLookup       OrganizationByIDLookup

	// IDToken, when wired, lets the authorization_code grant emit
	// an `id_token` in the response when the consented scope set
	// contains "openid" (OIDC Core §3.1.3.3). Without it, the
	// grant still returns the access token + an empty id_token
	// field (omitempty keeps it off the wire); the access flow
	// remains protocol-correct for plain OAuth 2.0.
	IDToken *service.IDTokenService

	// UserSession, when wired, lets the authorization_code grant
	// mint a `refresh_token` when the consented scope contains
	// the `offline_access` scope (OIDC Core §11). The minted
	// session is bound to the requesting OAuth client; rotation
	// proceeds via the existing /api/v1/auth/session/refresh
	// endpoint. Without it, offline_access in the consented scope
	// is silently dropped from the response.
	UserSession *service.UserSessionService

	// RefreshTokens, when wired, makes offline_access mint an OAUTH
	// refresh token — the kind the advertised refresh_token GRANT on
	// this very endpoint consumes and rotates. THE-PKCE-DECISION
	// conformance measurement (oidcc-refresh-token): the session-based
	// token above is redeemable ONLY at /api/v1/auth/session/refresh,
	// so a standard OAuth client that presented it at
	// grant_type=refresh_token always got invalid_grant — the grant
	// was advertised but unusable. When wired this takes precedence
	// over UserSession for the refresh_token response field.
	RefreshTokens *service.RefreshTokenService
}

// RegisterTokenRoutes mounts
//
//	POST /api/v1/oauth/token
//
// onto router. The route registers ONLY when BOTH TokenService
// and ClientAuth are wired — without either, the path 404s. This
// is a deliberate design choice: a token endpoint without client
// authentication is unsafe regardless of bearer-side guards, so
// the route never falls back to RequireSiteAdmin (unlike
// /introspection or /revoke, which have a documented stopgap).
func RegisterTokenRoutes(router gin.IRouter, deps TokenHandlerDeps) {
	if deps.TokenService == nil || deps.ClientAuth == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/oauth")
	// CONF-9: pre-auth IP-keyed limiter FIRST — see the PreAuthLimiter doc.
	if deps.PreAuthLimiter != nil {
		g.Use(deps.PreAuthLimiter)
	}
	g.Use(mw.RequireOAuthClient(deps.StartupReport, deps.ClientAuth))
	// Per-client rate limit runs AFTER client auth so it keys on the
	// authenticated client. Nil-safe (noop when unconfigured).
	if deps.Limiter != nil {
		g.Use(deps.Limiter)
	}

	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/token
	// docgen:summary=OAuth 2.1 token endpoint (authorization_code, refresh, client_credentials, token exchange).
	// docgen:tier=oss
	// docgen:auth=oauth_client
	g.POST("/token", HandleToken(deps))
}

// HandleToken implements the client_credentials grant per
// RFC 6749 §4.4. The handler:
//
//   - Sets `Cache-Control: no-store` and `Pragma: no-cache` per
//     RFC 6749 §5.1.
//   - Reads `grant_type`, `scope`, `audience` from
//     application/x-www-form-urlencoded body. JSON is NOT
//     accepted — the monolith's token endpoint is form-only and
//     OSS preserves that.
//   - Reads the authenticated client from gin.Context (planted by
//     mw.RequireOAuthClient).
//   - Calls TokenService.IssueClientCredentials and serialises
//     the result as a JSON body.
//   - On error, returns the canonical RFC 6749 §5.2 error envelope
//     `{"error":"...","error_description":"..."}`.
//   - On success, emits `oauth_token.issued` audit with safe
//     metadata (client_id, client_kind, grant_type, scopes_count,
//     token_type). The raw access token is NEVER written to
//     audit metadata, logged, or echoed in any error path.
func HandleToken(deps TokenHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		// RFC 6749 §5.1 — no caching of token responses.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		client, ok := mw.AuthenticatedClientFromContext(c)
		if !ok || client == nil {
			// RequireOAuthClient should have rejected before
			// reaching here; defense in depth.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
		grantType := c.PostForm("grant_type")
		var (
			resp *service.TokenResponse
			err  error
		)
		switch grantType {
		case "refresh_token":
			resp, err = deps.TokenService.IssueRefresh(c.Request.Context(), client, service.RefreshTokenRequest{
				GrantType:    grantType,
				RefreshToken: c.PostForm("refresh_token"),
			})
		case "authorization_code":
			resp, err = handleAuthorizationCodeGrant(c, deps)
		default:
			resp, err = deps.TokenService.IssueClientCredentials(c.Request.Context(), client, service.ClientCredentialsRequest{
				GrantType:         grantType,
				RequestedScope:    c.PostForm("scope"),
				RequestedAudience: c.PostForm("audience"),
			})
		}
		if err != nil {
			emitTokenError(c, err)
			return
		}
		// Safe audit event. NEVER include the raw access token.
		scopesCount := 0
		if resp.Scope != "" {
			scopesCount = len(splitWhitespace(resp.Scope))
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "oauth_token.issued",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":    client.ClientID,
				"client_kind":  string(client.Kind),
				"grant_type":   grantType,
				"scopes_count": scopesCount,
				"token_type":   resp.TokenType,
			},
		})
		c.JSON(http.StatusOK, resp)
	}
}

// emitTokenError maps a TokenService sentinel to the canonical
// RFC 6749 §5.2 error envelope. The wire body NEVER includes the
// sentinel's Go error message — only the canonical RFC error
// code. error_description carries a short, operator-facing hint.
func emitTokenError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrTokenServiceInvalidRequest):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "grant_type is required",
		})
	case errors.Is(err, service.ErrTokenServiceUnsupportedGrant):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type is not supported",
		})
	case errors.Is(err, service.ErrTokenServiceUnauthorizedClient):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for this grant",
		})
	case errors.Is(err, service.ErrTokenServiceInvalidGrant):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Refresh token is invalid, expired, revoked, or bound to a different client",
		})
	case errors.Is(err, service.ErrTokenServiceRefreshDisabled):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type is not supported",
		})
	case errors.Is(err, service.ErrAuthCodeInvalidGrant):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code is invalid, expired, consumed, or bound to a different client",
		})
	case errors.Is(err, service.ErrTokenServiceInvalidScope):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_scope",
			"error_description": "The requested scope is not valid or not allowed",
		})
	case errors.Is(err, service.ErrTokenServiceInvalidTarget):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_target",
			"error_description": "The requested audience is not registered or not active",
		})
	case errors.Is(err, service.ErrTokenServiceNoSigningKey),
		errors.Is(err, service.ErrTokenServiceSigningFailed):
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
	}
}

// handleAuthorizationCodeGrant runs the OSS authorization_code
// grant on the token endpoint. The flow:
//
//  1. Verify all 5 deps are wired (AuthCodeService, UserToken,
//     UserLookup, SessionLookup, OrgLookup). If any is missing,
//     return unsupported_grant_type — preserves the legacy posture.
//  2. Consume the auth code via AuthorizationCodeService.Consume
//     (validates client_id, redirect_uri, PKCE S256 verifier,
//     not-expired, not-consumed).
//  3. Load the session row via SessionLookup.GetByID for the
//     acr / auth_time claims.
//  4. Load the user row via UserLookup.GetByID for email / role /
//     org_id claims.
//     4a. Revalidate at exchange time (P0-2): the session must still be
//     usable (CanBeUsed), the user must still be live (CanLogin), and
//     the user's organization must still be operational
//     (IsOperational). Any failure returns invalid_grant — an
//     outstanding code MUST NOT outlive a revoked session, a
//     deleted/banned user, or a suspended/deleted tenant.
//  5. Mint the access token via UserTokenService.IssueForSession.
//  6. Return a TokenResponse (no refresh_token — the user-session
//     refresh lifecycle lives on the /api/v1/auth/session/refresh
//     surface, not on /oauth/token).
//
// /authorize is NOT implemented in this slice; this grant only
// succeeds for codes created via AuthorizationCodeService.Create
// (typically by a test fixture or a future /authorize handler).
func handleAuthorizationCodeGrant(c *gin.Context, deps TokenHandlerDeps) (*service.TokenResponse, error) {
	if deps.AuthCodeService == nil || deps.UserToken == nil ||
		deps.UserLookup == nil || deps.SessionLookup == nil ||
		deps.OrgLookup == nil {
		return nil, service.ErrTokenServiceUnsupportedGrant
	}
	client, _ := mw.AuthenticatedClientFromContext(c)
	if client == nil {
		return nil, service.ErrTokenServiceInvalidRequest
	}
	consumed, err := deps.AuthCodeService.Consume(c.Request.Context(), service.ConsumeAuthorizationCodeInput{
		Code:         c.PostForm("code"),
		ClientID:     client.ClientID,
		RedirectURI:  c.PostForm("redirect_uri"),
		CodeVerifier: c.PostForm("code_verifier"),
	})
	if err != nil {
		return nil, err
	}
	session, err := deps.SessionLookup.GetByID(c.Request.Context(), consumed.SessionID)
	if err != nil || session == nil {
		return nil, service.ErrAuthCodeInvalidGrant
	}
	user, err := deps.UserLookup.GetByID(c.Request.Context(), consumed.UserID)
	if err != nil || user == nil {
		return nil, service.ErrAuthCodeInvalidGrant
	}
	// P0-2: revalidate the principal + tenant at exchange time. A code
	// that was legitimately minted MUST STILL be refused if, in the
	// interval before exchange, its session was revoked/expired, its
	// user was deleted/banned, or its organization was
	// suspended/deleted — otherwise a revoked session could exchange an
	// outstanding code and, with offline_access, mint a fresh session
	// from a dead one. All three map to RFC 6749 §5.2 invalid_grant.
	now := time.Now().UTC()
	if ok, _ := session.CanBeUsed(now); !ok {
		return nil, service.ErrAuthCodeInvalidGrant
	}
	if ok, _ := user.CanLogin(false); !ok {
		return nil, service.ErrAuthCodeInvalidGrant
	}
	// A site_admin principal carries a nil organization and has no
	// tenant to gate; every tenant-scoped principal MUST belong to a
	// live organization (Active && not-deleted) per the reusable
	// domain.Organization.IsOperational predicate.
	if user.OrganizationID != uuid.Nil {
		org, orgErr := deps.OrgLookup.GetByID(c.Request.Context(), user.OrganizationID)
		if orgErr != nil || org == nil || !org.IsOperational() {
			return nil, service.ErrAuthCodeInvalidGrant
		}
	}
	// THE-CONSENTED-SCOPE (owner ruling): the access token's scope is the
	// CONSENTED scope INTERSECTED with what the user's ROLE permits — roles
	// authorize, consent restricts, consent never grants beyond the role.
	// The token-response `scope` reports exactly that effective set (RFC
	// 6749 §5.1), and the refresh token below carries it so rotation
	// preserves it.
	access, err := deps.UserToken.IssueForConsentedClient(c.Request.Context(), user, session, client.ClientID, consumed.Scope)
	if err != nil {
		return nil, err
	}
	effectiveScope := access.Scope
	resp := &service.TokenResponse{
		AccessToken: access.AccessToken,
		TokenType:   access.TokenType,
		ExpiresIn:   access.ExpiresIn,
		Scope:       effectiveScope,
	}
	// OIDC §3.1.3.3: when the consented scope contains "openid",
	// the token response MUST include an `id_token`. We treat an
	// IDTokenService error as a fatal server_error rather than
	// silently dropping the ID token — the client asked for OIDC
	// and would be misled by a plain OAuth response.
	if deps.IDToken != nil && hasOpenIDScope(consumed.Scope) {
		idt, idErr := deps.IDToken.Issue(c.Request.Context(), service.IDTokenInput{
			User:     user,
			Session:  session,
			Audience: client.ClientID,
			Nonce:    consumed.Nonce,
			Scope:    consumed.Scope,
			// The client's registered id_token_signed_response_alg
			// (default EdDSA). RS256 fires ONLY via this explicit
			// registration — testing-only (THE-PKCE-DECISION).
			SigningAlg: client.IDTokenAlg,
		})
		if idErr != nil {
			return nil, service.ErrTokenServiceSigningFailed
		}
		resp.IDToken = idt.IDToken
	}
	// OIDC §11: the offline_access scope SHOULD trigger a refresh
	// token. Preferred shape (THE-PKCE-DECISION): an OAUTH refresh
	// token from RefreshTokenService — the kind this endpoint's own
	// refresh_token grant consumes and rotates, so the token we hand
	// out is redeemable where we advertise it. Legacy fallback for
	// compositions without RefreshTokenService: the session-based
	// token, redeemable at /api/v1/auth/session/refresh only.
	var issuedRefreshID *uuid.UUID
	if hasOfflineAccessScope(consumed.Scope) {
		switch {
		case deps.RefreshTokens != nil:
			issued, refreshErr := deps.RefreshTokens.Issue(c.Request.Context(), service.IssueRefreshTokenInput{
				ClientID:  client.ClientID,
				Subject:   user.ID.String(),
				Scope:     effectiveScope,
				Audience:  consumed.Audience,
				AccessJTI: access.JTI,
			})
			if refreshErr == nil && issued != nil {
				resp.RefreshToken = issued.Token
				rid := issued.ID
				issuedRefreshID = &rid
			}
		case deps.UserSession != nil:
			clientIDCopy := client.ClientID
			maxSessions := 0
			if user.OrgMaxSessionsPerUser != nil {
				maxSessions = *user.OrgMaxSessionsPerUser
			}
			issued, refreshErr := deps.UserSession.CreateUserSession(c.Request.Context(), service.CreateUserSessionInput{
				UserID:             user.ID,
				ClientID:           &clientIDCopy,
				Acr:                session.EffectiveACR(),
				Amr:                session.Amr,
				MaxSessionsPerUser: maxSessions,
				OrganizationID:     user.OrganizationID,
				Role:               string(user.Role),
			})
			if refreshErr == nil && issued != nil {
				resp.RefreshToken = issued.RefreshToken
			}
		}
		// On error: leave refresh_token empty. The access token +
		// id_token still went out; the client can retry the
		// authorization with offline_access at the next /authorize.
	}
	// THE-CODE-REUSE-REVOKER (RFC 6749 §4.1.2): write back onto the
	// consumed code row what this exchange minted, so a replay of the code
	// revokes exactly these through AuthCodeReuseRevocation. Fail CLOSED:
	// nothing has been transmitted yet, so refusing here leaks no usable
	// token, whereas answering with tokens that could never be revoked on
	// reuse would. (The session-based legacy refresh token is not an OAuth
	// refresh row and is not recorded — its lifecycle is the session's.)
	if err := deps.AuthCodeService.RecordIssuedTokens(c.Request.Context(), consumed.ID, access.JTI, access.ExpiresAt, issuedRefreshID); err != nil {
		return nil, service.ErrTokenServiceSigningFailed
	}
	return resp, nil
}

// hasOpenIDScope reports whether the supplied space-separated
// scope string includes the OIDC `openid` scope.
func hasOpenIDScope(scope string) bool {
	if scope == "" {
		return false
	}
	return slices.Contains(splitWhitespace(scope), "openid")
}

// hasOfflineAccessScope reports whether the supplied space-separated
// scope string includes the OIDC `offline_access` scope (Core §11).
func hasOfflineAccessScope(scope string) bool {
	if scope == "" {
		return false
	}
	return slices.Contains(splitWhitespace(scope), "offline_access")
}

// splitWhitespace splits s on any whitespace and drops empty
// strings. Local helper to avoid the cost of strings.Fields on
// the audit hot path (we only need a count).
func splitWhitespace(s string) []string {
	out := make([]string, 0)
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
