package handlers

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ConsentHandlerDeps wires the interactive consent surface that
// supports the cookie-driven /authorize flow.
//
// ConsentService is REQUIRED; CookieSession is REQUIRED (consent
// is interactive — bearer-only callers do not see this page).
// AuthorizeService is REQUIRED so the POST-approve path can mint a
// code via the same validation pipeline /authorize uses.
type ConsentHandlerDeps struct {
	ConsentService   *service.ConsentService
	AuthorizeService *service.AuthorizeService
	CookieSession    *service.CookieSessionService
	Clients          ConsentClientLookup
	CSRF             *service.BrowserCSRFService
	Audit            audit.Service
}

// ConsentClientLookup is the seam the consent handlers use to
// resolve the client_id → display name + post-validation. Same
// shape as the AuthorizeService's client lookup.
type ConsentClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// RegisterConsentRoutes mounts the GET + POST consent endpoints.
// Both register together; neither registers if any required dep is
// missing.
func RegisterConsentRoutes(router gin.IRouter, deps ConsentHandlerDeps) {
	if deps.ConsentService == nil ||
		deps.AuthorizeService == nil ||
		deps.CookieSession == nil ||
		deps.Clients == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=GET
	// docgen:path=/api/v1/oauth/consent
	// docgen:summary=Interactive consent form (renders the minimal consent HTML for the authenticated user; echoes the /authorize query parameters through hidden form fields so the POST can resume the exact authorize request).
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Browser session cookie required. Anonymous callers are redirected to /api/v1/auth/browser-login.
	router.GET("/api/v1/oauth/consent", HandleConsentForm(deps))

	// docgen:endpoint
	// docgen:surface=oauth
	// docgen:method=POST
	// docgen:path=/api/v1/oauth/consent
	// docgen:summary=Submit interactive consent — on accept, redirects back to the original /authorize flow with an authorization_code; on deny, returns the access_denied error envelope.
	// docgen:tier=oss
	// docgen:auth=session
	router.POST("/api/v1/oauth/consent", HandleConsentSubmit(deps))
}

// HandleConsentForm renders the minimal consent HTML for the
// authenticated user. The /authorize query parameters are echoed
// through hidden form fields so the POST can resume the exact
// /authorize call.
//
// Requires a cookie-resolved session OR a bearer principal. Without
// either, returns 401 — the user must complete the browser login
// before seeing the consent screen.
func HandleConsentForm(deps ConsentHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := resolveConsentPrincipal(c, deps.CookieSession)
		if principal == nil {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required"})
			return
		}
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		if clientID == "" || redirectURI == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		client, err := deps.Clients.GetClientByClientID(c.Request.Context(), clientID)
		if err != nil || client == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		// Redirect URI must already be in the client's allowlist —
		// defence in depth so a forged consent submission cannot
		// land a code at an unregistered URI.
		if !client.IsRedirectURIAllowed(redirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		var csrfToken string
		if deps.CSRF != nil {
			if tok, cookie, err := deps.CSRF.Issue(); err == nil {
				csrfToken = tok
				writeBrowserCSRFCookie(c, cookie)
			}
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Status(http.StatusOK)
		renderConsentForm(c.Writer, client, c.Request.URL.Query(), csrfToken)
	}
}

// HandleConsentSubmit processes the approve/deny decision. On
// approve, the slice persists the consent row, then drives
// AuthorizeService.Authorize against the echoed /authorize
// parameters — which now finds a covering consent row and mints a
// code. On deny, it builds the access_denied redirect.
//
// Sensitive-field safety: the form fields are echoed back into the
// /authorize request struct, but the raw code (when minted) is
// never written to logs/audit. The audit event carries client_id +
// outcome only.
func HandleConsentSubmit(deps ConsentHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := resolveConsentPrincipal(c, deps.CookieSession)
		if principal == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "login_required"})
			return
		}
		if deps.CSRF != nil {
			cookieVal := readCSRFCookie(c.Request, deps.CSRF.CookieName())
			formVal := c.PostForm(deps.CSRF.FormFieldName())
			if err := deps.CSRF.Verify(cookieVal, formVal); err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "csrf_failed"})
				return
			}
		}
		action := strings.ToLower(c.PostForm("action"))
		req := readConsentForm(c)
		req.Principal = principal

		if action == "deny" {
			handleConsentDeny(c, deps, req)
			return
		}

		// R6: clamp the requested scope to the client's registered scopes
		// BEFORE persisting consent — the same narrowing AuthorizeService
		// applies when minting the code — so the stored consent never
		// records scopes the client is not registered for. Reuses the
		// existing client-lookup seam (deps.Clients); a lookup miss leaves
		// req.Scope unchanged (Authorize re-applies the clamp authoritatively
		// when it mints the code, so the token response is still narrowed).
		if client, cerr := deps.Clients.GetClientByClientID(c.Request.Context(), req.ClientID); cerr == nil && client != nil {
			req.Scope = service.ClampScopeToRegistered(req.Scope, client.Scope)
		}

		// Approve: persist consent, then drive /authorize to mint
		// the code.
		if _, err := deps.ConsentService.Grant(c.Request.Context(), service.GrantConsentInput{
			UserID:         principal.UserID,
			OrganizationID: orgIDPtrIfPresent(principal.OrganizationID),
			ClientID:       req.ClientID,
			Audience:       req.Audience,
			Scope:          req.Scope,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "oauth_consent.granted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":    req.ClientID,
				"scopes_count": len(splitWhitespace(req.Scope)),
			},
		})
		result, err := deps.AuthorizeService.Authorize(c.Request.Context(), req)
		if err != nil {
			emitAuthorizeError(c, AuthorizeHandlerDeps{AuthorizeService: deps.AuthorizeService, Audit: deps.Audit}, req, authorizeQueryFromRequest(req), err)
			return
		}
		c.Redirect(http.StatusFound, result.RedirectURL)
	}
}

// handleConsentDeny builds the access_denied redirect via the
// AuthorizeService URL builder so the URL construction stays in one
// place.
func handleConsentDeny(c *gin.Context, deps ConsentHandlerDeps, req service.AuthorizeRequest) {
	location, err := deps.AuthorizeService.BuildErrorRedirect(req.RedirectURI, "access_denied", req.State)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    "oauth_consent.denied",
		Outcome:   "denied",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata: map[string]any{
			"client_id": req.ClientID,
		},
	})
	c.Redirect(http.StatusFound, location)
}

// resolveConsentPrincipal mirrors the /authorize handler's bearer-
// then-cookie resolution but returns a *domain.Principal directly.
func resolveConsentPrincipal(c *gin.Context, cookie *service.CookieSessionService) *domain.Principal {
	if p, ok := mw.PrincipalFromContext(c); ok {
		return p
	}
	if cookie == nil {
		return nil
	}
	cookieVal, ok := cookie.Read(c.Request)
	if !ok {
		return nil
	}
	resolved, err := cookie.Resolve(c.Request.Context(), cookieVal)
	if err != nil || resolved == nil || resolved.Session == nil || resolved.User == nil {
		return nil
	}
	return principalFromCookieSession(resolved)
}

// readConsentForm extracts the /authorize parameters from either
// the URL query (GET-style) or the form body (POST).
func readConsentForm(c *gin.Context) service.AuthorizeRequest {
	return service.AuthorizeRequest{
		ResponseType:        firstNonEmpty(c.PostForm("response_type"), c.Query("response_type")),
		ClientID:            firstNonEmpty(c.PostForm("client_id"), c.Query("client_id")),
		RedirectURI:         firstNonEmpty(c.PostForm("redirect_uri"), c.Query("redirect_uri")),
		Scope:               firstNonEmpty(c.PostForm("scope"), c.Query("scope")),
		Audience:            firstNonEmpty(c.PostForm("audience"), c.Query("audience")),
		State:               firstNonEmpty(c.PostForm("state"), c.Query("state")),
		Nonce:               firstNonEmpty(c.PostForm("nonce"), c.Query("nonce")),
		CodeChallenge:       firstNonEmpty(c.PostForm("code_challenge"), c.Query("code_challenge")),
		CodeChallengeMethod: firstNonEmpty(c.PostForm("code_challenge_method"), c.Query("code_challenge_method")),
		// THE-SECOND-LOGIN: the resumed request keeps max_age so the
		// post-consent re-run applies the same freshness rule.
		MaxAge: firstNonEmpty(c.PostForm("max_age"), c.Query("max_age")),
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orgIDPtrIfPresent(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	cp := id
	return &cp
}

// consentFormTemplate is the minimal consent HTML. The form echoes
// every /authorize parameter so POST can resume.
const consentFormTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>Authorize {{CLIENT_NAME}}</title>
</head>
<body>
  <main>
    <h1>Authorize {{CLIENT_NAME}}</h1>
    <p>{{CLIENT_NAME}} is requesting access to your account.</p>
    <h2>Requested scopes</h2>
    <ul>{{SCOPES}}</ul>
    <form method="POST" action="/api/v1/oauth/consent">
      {{HIDDEN}}
      {{CSRF}}
      <button type="submit" name="action" value="approve">Approve</button>
      <button type="submit" name="action" value="deny">Deny</button>
    </form>
  </main>
</body>
</html>`

func renderConsentForm(w http.ResponseWriter, client *domain.Client, q url.Values, csrfToken string) {
	clientName := client.Name
	if clientName == "" {
		clientName = client.ClientID
	}
	body := strings.ReplaceAll(consentFormTemplate, "{{CLIENT_NAME}}", html.EscapeString(clientName))
	body = strings.ReplaceAll(body, "{{SCOPES}}", renderScopes(q.Get("scope")))
	body = strings.ReplaceAll(body, "{{HIDDEN}}", renderHiddenFields(q))
	csrfInput := ""
	if csrfToken != "" {
		csrfInput = `<input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `">`
	}
	body = strings.ReplaceAll(body, "{{CSRF}}", csrfInput)
	_, _ = w.Write([]byte(body))
}

func renderScopes(scope string) string {
	tokens := strings.Fields(scope)
	if len(tokens) == 0 {
		return "<li>(no scope requested)</li>"
	}
	var b strings.Builder
	for _, t := range tokens {
		b.WriteString("<li>")
		b.WriteString(html.EscapeString(t))
		b.WriteString("</li>")
	}
	return b.String()
}

func renderHiddenFields(q url.Values) string {
	keys := []string{
		"response_type", "client_id", "redirect_uri", "scope", "audience",
		"state", "nonce", "code_challenge", "code_challenge_method",
	}
	var b strings.Builder
	for _, k := range keys {
		v := q.Get(k)
		if v == "" {
			continue
		}
		b.WriteString(`<input type="hidden" name="`)
		b.WriteString(k)
		b.WriteString(`" value="`)
		b.WriteString(html.EscapeString(v))
		b.WriteString(`">`)
	}
	return b.String()
}

// errInvalidConsent is a placeholder for future direct-path
// validation errors. Currently unused but kept so that downstream
// branches can resolve without rebuilding the file.
var errInvalidConsent = errors.New("consent invalid")
var _ = errInvalidConsent
