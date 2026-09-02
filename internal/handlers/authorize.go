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
	// RequestObjects resolves OIDC §6 `request=<JWT>` objects into merged
	// parameters BEFORE the request is read (THE-JAR-REQUEST-OBJECT). nil →
	// request objects stay refused with request_not_supported.
	RequestObjects *service.RequestObjectService
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
		values := c.Request.URL.Query()
		if c.Request.Method == http.MethodPost {
			_ = c.Request.ParseForm()
			values = c.Request.PostForm
		}
		// THE-JAR-REQUEST-OBJECT (OIDC Core §6 / RFC 9101): a `request`
		// object is verified and MERGED into the parameters here, so every
		// value it carries reaches exactly the same parsing the query path
		// uses (scope clamping, PKCE, claims, acr_values, max_age). Without
		// the service the object stays refused downstream (request_not_supported).
		rawRequest := values.Get("request")
		if rawRequest != "" && deps.RequestObjects != nil {
			merged, redirectSafe, rerr := deps.RequestObjects.Resolve(c.Request.Context(), values)
			if rerr != nil {
				emitRequestObjectError(c, deps, values, redirectSafe, rerr)
				return
			}
			values = merged
			rawRequest = ""
		}
		param := values.Get
		authorizeQuery := resumableAuthorizeQuery(values)

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
			AcrValues:           param("acr_values"),
			RequestObject:       rawRequest,
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
	// THE-HONEST-ACR: acr_values is honored, so it must resume too.
	set("acr_values", req.AcrValues)
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
	case errors.Is(err, service.ErrAuthorizeUnmetAuthenticationRequirements):
		// THE-HONEST-ACR: a requested, known context this user cannot
		// perform (TOTP rung without an enrolled authenticator; the
		// phishing-resistant rung, which has no step-up ceremony). The
		// honest OIDC error (Unmet Authentication Requirements 1.0),
		// never a fabricated acr.
		redirectAuthorizeError(c, deps, req, "unmet_authentication_requirements")
	case errors.Is(err, service.ErrAuthorizeStepUpRequired):
		// THE-HONEST-ACR: the session is below the requested known
		// rung and the user CAN perform it (TOTP enrolled). An
		// interactive browser is sent through the OP's own step-up
		// ceremony carrying the full authorize URL as return_to; the
		// verified TOTP records the uplift on the SAME session and the
		// resumed request passes. prompt=none forbids interaction:
		// login_required per OIDC Core §3.1.2.6.
		if strings.TrimSpace(req.Prompt) != "none" {
			// THE-PHISHING-RESISTANT-ACR: the service names the ceremony that
			// reaches the requested rung — TOTP (default) or passkey.
			ceremony := "/api/v1/auth/step-up"
			var stepUp *service.StepUpRequiredError
			if errors.As(err, &stepUp) && stepUp.Method == service.StepUpMethodPasskey {
				ceremony = "/api/v1/auth/step-up/passkey"
			}
			c.Redirect(http.StatusFound,
				ceremony+"?return_to="+url.QueryEscape("/api/v1/oauth/authorize?"+authorizeQuery))
			return
		}
		redirectAuthorizeError(c, deps, req, "login_required")
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
			// THE-JAR-REQUEST-OBJECT: when login WAS forced, the login URL
			// itself says so (`&prompt=login`, outside return_to) — an
			// honest marker for the login page and for the conformance
			// browser, which must screenshot exactly that forced login
			// (oidcc-prompt-login waits for it). The login form ignores it.
			resumed, forced := stripPromptLogin(authorizeQuery)
			loc := "/api/v1/auth/browser-login?return_to=" + url.QueryEscape("/api/v1/oauth/authorize?"+resumed)
			if forced {
				loc += "&prompt=login"
			}
			c.Redirect(http.StatusFound, loc)
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
// re-encoded only when something was removed. The second result reports
// whether `login` WAS removed (the login was forced by the client).
func stripPromptLogin(rawQuery string) (string, bool) {
	v, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery, false
	}
	tokens := strings.Fields(v.Get("prompt"))
	kept := make([]string, 0, len(tokens))
	for _, p := range tokens {
		if !strings.EqualFold(p, "login") {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(tokens) {
		return rawQuery, false
	}
	if len(kept) == 0 {
		v.Del("prompt")
	} else {
		v.Set("prompt", strings.Join(kept, " "))
	}
	return v.Encode(), true
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
// resumableAuthorizeQuery re-encodes the (merged) parameters for the
// login/consent return_to. `request` / `request_uri` are dropped: the
// object was verified and merged once; the resumed GET carries plain
// parameters, exactly like a POST is re-encoded.
func resumableAuthorizeQuery(values url.Values) string {
	v := url.Values{}
	for k, vals := range values {
		if k == "request" || k == "request_uri" {
			continue
		}
		v[k] = append([]string(nil), vals...)
	}
	return v.Encode()
}

// emitRequestObjectError answers a request-object failure (THE-JAR-REQUEST-
// OBJECT). Unknown client / missing client_id → direct 400 (no trusted
// redirect_uri exists). An unverifiable object → invalid_request_object,
// redirected ONLY when the QUERY redirect_uri is registered for the client
// (the object's own redirect_uri cannot be trusted before it verifies);
// otherwise a direct 400 — never an open redirect.
func emitRequestObjectError(c *gin.Context, deps AuthorizeHandlerDeps, values url.Values, redirectSafe bool, err error) {
	req := service.AuthorizeRequest{
		ClientID:    values.Get("client_id"),
		RedirectURI: values.Get("redirect_uri"),
		State:       values.Get("state"),
	}
	switch {
	case errors.Is(err, service.ErrAuthorizeMissingParameters):
		respondAuthorizeDirectError(c, "invalid_request", "client_id is required alongside a request object")
	case errors.Is(err, service.ErrAuthorizeInvalidClient):
		respondAuthorizeDirectError(c, "invalid_client", "Unknown or inactive client")
	case errors.Is(err, service.ErrAuthorizeInvalidRequestObject) && redirectSafe:
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action: "oauth_authorize.request_object_rejected", Outcome: "denied",
			IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{"client_id": req.ClientID},
		})
		redirectAuthorizeError(c, deps, req, "invalid_request_object")
	default:
		respondAuthorizeDirectError(c, "invalid_request_object", "The request object could not be verified")
	}
}

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
