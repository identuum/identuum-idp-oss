package handlers

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"

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
//	GET  /api/v1/oauth/authorize
//	POST /api/v1/oauth/authorize
//
// onto router. The routes register ONLY when AuthorizeService is
// wired. POST is required by OIDC Core §3.1.2.1 (the Authorization
// Server MUST support both GET and form-serialized POST); the
// conformance suite exercises it via oidcc-ensure-post-request-succeeds.
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
	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/authorize
	// docgen:summary=OIDC Core §3.1.2.1 form-serialized variant of the authorize endpoint — identical semantics to GET with parameters in the request body.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Login/consent redirects rebuild the request as a GET authorize URL carrying every submitted parameter, so the resumed ceremony is identical to the GET flow.
	router.POST("/api/v1/oauth/authorize", HandleAuthorize(deps))
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

		// OIDC Core §3.1.2.1: parameters arrive as query (GET) or as a
		// form-serialized body (POST). param reads either; authorizeQuery
		// is the canonical query string the login/consent redirects loop
		// back through — for POST it re-encodes EVERY submitted form
		// parameter (not just the ones this handler reads) so the resumed
		// GET carries the request unchanged.
		param := c.Query
		authorizeQuery := c.Request.URL.RawQuery
		if c.Request.Method == http.MethodPost {
			param = c.PostForm
			_ = c.Request.ParseForm()
			authorizeQuery = c.Request.PostForm.Encode()
		}

		req := service.AuthorizeRequest{
			ResponseType:        param("response_type"),
			ClientID:            param("client_id"),
			RedirectURI:         param("redirect_uri"),
			Scope:               param("scope"),
			Audience:            param("audience"),
			State:               param("state"),
			Nonce:               param("nonce"),
			CodeChallenge:       param("code_challenge"),
			CodeChallengeMethod: param("code_challenge_method"),
			Prompt:              param("prompt"),
			MaxAge:              param("max_age"),
			Claims:              param("claims"),
			RequestObject:       param("request"),
			RequestURIParam:     param("request_uri"),
			Principal:           principal,
		}

		result, err := deps.AuthorizeService.Authorize(c.Request.Context(), req)
		if err != nil {
			emitAuthorizeError(c, deps, req, authorizeQuery, err)
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

// authorizeQueryFromRequest re-encodes an AuthorizeRequest's wire
// parameters as a canonical authorize query string. Used where the
// original raw query is no longer available (the consent-approve POST),
// so an error path can still rebuild the authorize URL for redirects.
func authorizeQueryFromRequest(req service.AuthorizeRequest) string {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}
	set("response_type", req.ResponseType)
	set("client_id", req.ClientID)
	set("redirect_uri", req.RedirectURI)
	set("scope", req.Scope)
	set("audience", req.Audience)
	set("state", req.State)
	set("nonce", req.Nonce)
	set("code_challenge", req.CodeChallenge)
	set("code_challenge_method", req.CodeChallengeMethod)
	set("prompt", req.Prompt)
	// THE-PROFILE-CLAIMS item 0: max_age is an honored parameter — the
	// re-encoded query (login/consent redirects from the consent-approve
	// path) must carry it, or the freshness requirement is lost.
	set("max_age", req.MaxAge)
	set("claims", req.Claims)
	return v.Encode()
}

// emitAuthorizeError maps an AuthorizeService sentinel to the
// correct response shape. authorizeQuery is the canonical query string
// of the authorize request (the raw GET query, or the re-encoded POST
// form) used to rebuild the request behind the login/consent redirects.
func emitAuthorizeError(c *gin.Context, deps AuthorizeHandlerDeps, req service.AuthorizeRequest, authorizeQuery string, err error) {
	switch {
	// Pre-redirect-uri failures → 400 direct. These render for the HUMAN
	// at the browser (there is no validated redirect_uri to send them
	// back through), so a browser gets a small HTML error page; API
	// clients keep the JSON envelope.
	case errors.Is(err, service.ErrAuthorizeMissingParameters):
		respondAuthorizeDirectError(c, "invalid_request", "Missing required parameter")
	case errors.Is(err, service.ErrAuthorizeInvalidClient):
		respondAuthorizeDirectError(c, "invalid_client", "Unknown or inactive client")
	case errors.Is(err, service.ErrAuthorizeInvalidRedirectURI):
		respondAuthorizeDirectError(c, "invalid_request", "redirect_uri is not registered for this client")

	// Redirect-safe failures → 302 with error= + state=.
	case errors.Is(err, service.ErrAuthorizeUnsupportedResponseType):
		redirectAuthorizeError(c, deps, req, "unsupported_response_type")
	case errors.Is(err, service.ErrAuthorizeUnsupportedChallenge):
		redirectAuthorizeError(c, deps, req, "invalid_request")
	case errors.Is(err, service.ErrAuthorizeInvalidScope):
		redirectAuthorizeError(c, deps, req, "invalid_scope")
	case errors.Is(err, service.ErrAuthorizeInvalidTarget):
		redirectAuthorizeError(c, deps, req, "invalid_target")
	case errors.Is(err, service.ErrAuthorizeRequestNotSupported):
		redirectAuthorizeError(c, deps, req, "request_not_supported")
	case errors.Is(err, service.ErrAuthorizeRequestURINotSupported):
		redirectAuthorizeError(c, deps, req, "request_uri_not_supported")
	case errors.Is(err, service.ErrAuthorizeInvalidMaxAge), errors.Is(err, service.ErrAuthorizeInvalidClaims):
		redirectAuthorizeError(c, deps, req, "invalid_request")
	case errors.Is(err, service.ErrAuthorizeLoginRequired):
		// THE-PKCE-DECISION (DO-3): an unauthenticated BROWSER is sent to
		// the OP's own login form with the full authorize URL as return_to,
		// so the ceremony continues where it began — this is what any
		// interactive flow (and the conformance suite's browser) needs.
		// prompt=none keeps the error redirect: OIDC 3.1.2.6 REQUIRES
		// login_required back to the client when no interaction is allowed.
		if strings.TrimSpace(req.Prompt) != "none" {
			// THE-SECOND-LOGIN: the ceremony satisfies prompt=login ONCE —
			// the resumed request must not carry it, or login would be
			// forced forever. max_age stays: a fresh session passes it.
			c.Redirect(http.StatusFound,
				"/api/v1/auth/browser-login?return_to="+url.QueryEscape("/api/v1/oauth/authorize?"+stripPromptLogin(authorizeQuery)))
			return
		}
		redirectAuthorizeError(c, deps, req, "login_required")
	case errors.Is(err, service.ErrAuthorizeConsentRequired):
		// Same shape as login_required below: an interactive browser is
		// sent to the OP's OWN consent form carrying the full authorize
		// query (readConsentForm reads the same parameter names), so
		// approve mints the code and completes the ceremony. prompt=none
		// keeps the OIDC-required error redirect.
		if strings.TrimSpace(req.Prompt) != "none" {
			c.Redirect(http.StatusFound,
				"/api/v1/oauth/consent?"+authorizeQuery)
			return
		}
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

// stripPromptLogin removes the consumed `login` token from the prompt
// parameter of an authorize query (OIDC Core §3.1.2.1: prompt is a
// space-separated list). The OP satisfies prompt=login by running the
// ceremony ONCE; a return_to that still carried it would force login
// forever. Every other token and parameter survives; the query is
// re-encoded only when something was removed.
func stripPromptLogin(rawQuery string) string {
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	tokens := strings.Fields(v.Get("prompt"))
	kept := make([]string, 0, len(tokens))
	for _, p := range tokens {
		if !strings.EqualFold(p, "login") {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(tokens) {
		return rawQuery
	}
	if len(kept) == 0 {
		v.Del("prompt")
	} else {
		v.Set("prompt", strings.Join(kept, " "))
	}
	return v.Encode()
}

// respondAuthorizeDirectError answers a pre-redirect-uri authorize
// failure. These errors are shown to the HUMAN at the browser — OIDC
// Core §3.1.2.4: without a validated redirect_uri the OP MUST NOT
// redirect and SHOULD inform the end-user — so a client that accepts
// text/html gets a minimal HTML error page; everything else keeps the
// 400 JSON envelope. The HTML variant is served with 200: it is a
// terminal human-facing page, not a protocol response (no status is
// mandated for it), and browsers — including the conformance suite's
// scripted HtmlUnit, which THROWS on 4xx by default — must be able to
// render it. Never a redirect either way.
func respondAuthorizeDirectError(c *gin.Context, code, description string) {
	if strings.Contains(c.GetHeader("Accept"), "text/html") {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(
			`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`+
				`<title>Authorization error</title></head><body><main>`+
				`<h1>Authorization error</h1>`+
				`<p>error: `+html.EscapeString(code)+`</p>`+
				`<p>`+html.EscapeString(description)+`</p>`+
				`</main></body></html>`))
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             code,
		"error_description": description,
	})
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
