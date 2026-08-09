package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// principalFromCookieSession synthesises a *domain.Principal from a
// cookie-resolved (Session, User) pair. The synthesised Principal
// mirrors the shape the bearer middleware would have produced from
// the equivalent JWT, so downstream service code does not have to
// branch on "where did this principal come from?".
func principalFromCookieSession(r *service.CookieSessionLookupResult) *domain.Principal {
	if r == nil || r.Session == nil || r.User == nil {
		return nil
	}
	return &domain.Principal{
		UserID:         r.User.ID,
		OrganizationID: r.User.OrganizationID,
		SessionID:      r.Session.ID,
		Email:          r.User.Email,
		Role:           r.User.Role,
	}
}

// AuthorizeHandlerDeps wires the OSS GET /api/v1/oauth/authorize
// route.
//
// AuthorizeService is required; without it the route is NOT
// registered. Audit defaults to NoopService.
//
// Session mechanism: the handler resolves the authenticated
// principal in this deterministic order, stopping at the first
// success:
//
//  1. `*domain.Principal` planted by `mw.BearerPrincipal` upstream
//     (Authorization: Bearer <jwt>).
//  2. browser cookie via `CookieSession.Read` + `CookieSession.Resolve`
//     — the cookie value is the user-session refresh token in its
//     existing wire shape; resolution maps it back to (Session, User)
//     and synthesises a Principal mirroring what the bearer path
//     would have produced.
//
// A request without either is treated as unauthenticated and either
// redirects with login_required (when the redirect_uri has already
// been validated) or returns 400 (before validation).
type AuthorizeHandlerDeps struct {
	AuthorizeService *service.AuthorizeService
	CookieSession    *service.CookieSessionService
	Audit            audit.Service
}

// RegisterAuthorizeRoutes mounts
//
//	GET /api/v1/oauth/authorize
//
// onto router. The route registers ONLY when AuthorizeService is
// wired.
func RegisterAuthorizeRoutes(router gin.IRouter, deps AuthorizeHandlerDeps) {
	if deps.AuthorizeService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=GET
	// docgen:path=/api/v1/oauth/authorize
	// docgen:summary=OAuth 2.1 authorize endpoint — validates the request and either redirects to login, prompts for consent, or returns an authorization_code via redirect.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Anonymous callers are redirected to /api/v1/auth/browser-login; the route itself runs the AuthorizeService validation pipeline whether or not a session cookie is present.
	router.GET("/api/v1/oauth/authorize", HandleAuthorize(deps))
}

// HandleAuthorize is the OSS /authorize Gin handler. It runs the
// AuthorizeService validation pipeline and translates the result
// into either:
//
//   - 302 Location: <redirect_uri>?code=...&state=...&iss=... on
//     success.
//   - 302 Location: <redirect_uri>?error=...&state=...&iss=... for
//     redirect-safe sentinels (only after redirect_uri has been
//     validated against the client allowlist).
//   - 400 + JSON `{"error":"..."}` for invalid_client /
//     invalid_redirect_uri / missing_parameters — failures before
//     redirect_uri validation, where a redirect would invite an
//     open-redirect attack.
//   - 401 + JSON `{"error":"login_required"}` when the caller has
//     no bearer principal AND the redirect_uri was not yet
//     validated. (Once redirect_uri is validated, login_required
//     becomes a redirect.)
//
// Audit metadata: client_id, response_type, scopes_count. The raw
// code is NEVER written to logs/audit. The redirect URL is built
// once and surfaces only in the Location header.
func HandleAuthorize(deps AuthorizeHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, _ := mw.PrincipalFromContext(c)
		if principal == nil && deps.CookieSession != nil {
			if cookieVal, ok := deps.CookieSession.Read(c.Request); ok {
				resolved, err := deps.CookieSession.Resolve(c.Request.Context(), cookieVal)
				if err == nil && resolved != nil && resolved.Session != nil && resolved.User != nil {
					principal = principalFromCookieSession(resolved)
				}
			}
		}

		req := service.AuthorizeRequest{
			ResponseType:        c.Query("response_type"),
			ClientID:            c.Query("client_id"),
			RedirectURI:         c.Query("redirect_uri"),
			Scope:               c.Query("scope"),
			Audience:            c.Query("audience"),
			State:               c.Query("state"),
			Nonce:               c.Query("nonce"),
			CodeChallenge:       c.Query("code_challenge"),
			CodeChallengeMethod: c.Query("code_challenge_method"),
			Prompt:              c.Query("prompt"),
			Principal:           principal,
		}

		result, err := deps.AuthorizeService.Authorize(c.Request.Context(), req)
		if err != nil {
			emitAuthorizeError(c, deps, req, err)
			return
		}

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "oauth_authorize.code_issued",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":     result.ClientID,
				"response_type": "code",
				"scopes_count":  len(splitWhitespace(req.Scope)),
			},
		})
		c.Redirect(http.StatusFound, result.RedirectURL)
	}
}

// emitAuthorizeError maps an AuthorizeService sentinel to the
// correct response shape.
func emitAuthorizeError(c *gin.Context, deps AuthorizeHandlerDeps, req service.AuthorizeRequest, err error) {
	switch {
	// Pre-redirect-uri failures → 400 direct.
	case errors.Is(err, service.ErrAuthorizeMissingParameters):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameter",
		})
	case errors.Is(err, service.ErrAuthorizeInvalidClient):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown or inactive client",
		})
	case errors.Is(err, service.ErrAuthorizeInvalidRedirectURI):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "redirect_uri is not registered for this client",
		})

	// Redirect-safe failures → 302 with error= + state=.
	case errors.Is(err, service.ErrAuthorizeUnsupportedResponseType):
		redirectAuthorizeError(c, deps, req, "unsupported_response_type")
	case errors.Is(err, service.ErrAuthorizeUnsupportedChallenge):
		redirectAuthorizeError(c, deps, req, "invalid_request")
	case errors.Is(err, service.ErrAuthorizeInvalidScope):
		redirectAuthorizeError(c, deps, req, "invalid_scope")
	case errors.Is(err, service.ErrAuthorizeInvalidTarget):
		redirectAuthorizeError(c, deps, req, "invalid_target")
	case errors.Is(err, service.ErrAuthorizeLoginRequired):
		redirectAuthorizeError(c, deps, req, "login_required")
	case errors.Is(err, service.ErrAuthorizeConsentRequired):
		redirectAuthorizeError(c, deps, req, "consent_required")
	case errors.Is(err, service.ErrAuthorizeServerError):
		redirectAuthorizeError(c, deps, req, "server_error")
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Internal server error",
		})
	}
}

// redirectAuthorizeError builds and emits a 302 to redirect_uri with
// error= + state=. If URL construction fails (the redirect_uri was
// somehow unparseable after passing the client allowlist), fall back
// to a direct 400 — never silently drop the request.
func redirectAuthorizeError(c *gin.Context, deps AuthorizeHandlerDeps, req service.AuthorizeRequest, code string) {
	location, err := deps.AuthorizeService.BuildErrorRedirect(req.RedirectURI, code, req.State)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             code,
			"error_description": "redirect_uri is not a parseable URL",
		})
		return
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    "oauth_authorize.error_redirect",
		Outcome:   "denied",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata: map[string]any{
			"client_id": req.ClientID,
			"error":     code,
		},
	})
	c.Redirect(http.StatusFound, location)
}
