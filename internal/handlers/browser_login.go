package handlers

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// BrowserLoginHandlerDeps wires the server-rendered login form
// that backs the cookie-based /authorize flow.
//
// LocalLogin is REQUIRED; CookieSession is REQUIRED. CSRF is
// OPTIONAL — when wired, the POST submit path enforces a
// double-submit CSRF check; the GET form path renders the token
// into a hidden input + plants the cookie. Audit defaults to
// NoopService.
type BrowserLoginHandlerDeps struct {
	LocalLogin    *service.LocalLoginService
	CookieSession *service.CookieSessionService
	CSRF          *service.BrowserCSRFService
	// BrowserTokens, when wired, swaps the cookie value from the
	// raw user-session refresh token to an opaque browser-session
	// token that maps back to the session via the
	// browser_session_tokens indirection table. Refresh tokens
	// then never leave the JSON `/api/v1/auth/session/refresh`
	// surface.
	BrowserTokens *service.BrowserSessionTokenService
	Audit         audit.Service
}

// RegisterBrowserLoginRoutes mounts
//
//	GET  /api/v1/auth/browser-login
//	POST /api/v1/auth/browser-login
//
// onto router. Both routes register together. The path is distinct
// from the existing JSON `/api/v1/auth/login` route so an SPA
// driving the JSON endpoint and a browser driving the HTML endpoint
// can coexist without content-type-sniffing magic.
func RegisterBrowserLoginRoutes(router gin.IRouter, deps BrowserLoginHandlerDeps) {
	if deps.LocalLogin == nil || deps.CookieSession == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=GET
	// docgen:path=/api/v1/auth/browser-login
	// docgen:summary=Render the browser login form (anonymous; the form posts to the matching POST endpoint).
	// docgen:tier=oss
	// docgen:auth=public
	router.GET("/api/v1/auth/browser-login", HandleBrowserLoginForm(deps))

	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=POST
	// docgen:path=/api/v1/auth/browser-login
	// docgen:summary=Submit the browser login form (verifies credentials and establishes a browser session cookie on success).
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Anonymous endpoint — credentials live in the form body; the handler rate-limits brute-force attempts and emits an audit event.
	router.POST("/api/v1/auth/browser-login", HandleBrowserLoginSubmit(deps))
}

// HandleBrowserLoginForm renders the minimal HTML login form. The
// form preserves the `return_to` query parameter as a hidden input
// so a POST round-trip can resume the original /authorize URL after
// successful authentication.
//
// The form posts back to the same path. error= is shown as a
// generic message (no user-enumeration oracle).
func HandleBrowserLoginForm(deps BrowserLoginHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		returnTo := c.Query("return_to")
		errCode := c.Query("error")
		var csrfToken string
		if deps.CSRF != nil {
			tok, cookie, err := deps.CSRF.Issue()
			if err == nil {
				csrfToken = tok
				writeBrowserCSRFCookie(c, cookie)
			}
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Status(http.StatusOK)
		renderLoginForm(c.Writer, returnTo, errCode, csrfToken)
	}
}

// HandleBrowserLoginSubmit accepts the form POST, runs the existing
// LocalLoginService, plants the session cookie on success, and
// redirects the browser to `return_to` (or `/` when absent). On
// failure the form is re-rendered with a generic error code.
//
// `return_to` is restricted to same-origin relative paths to defeat
// open-redirect; anything starting with a scheme or "//" is treated
// as missing and the user lands at "/".
func HandleBrowserLoginSubmit(deps BrowserLoginHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		// CSRF: when wired, double-submit cookie + hidden field
		// MUST verify before any credential touches the wire.
		if deps.CSRF != nil {
			cookieVal := readCSRFCookie(c.Request, deps.CSRF.CookieName())
			formVal := c.PostForm(deps.CSRF.FormFieldName())
			if err := deps.CSRF.Verify(cookieVal, formVal); err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "csrf_failed"})
				return
			}
		}
		email := c.PostForm("email")
		password := c.PostForm("password")
		totp := c.PostForm("totp_code")
		remember := c.PostForm("remember_me") == "1" || c.PostForm("remember_me") == "true"
		returnTo := validateReturnTo(c.PostForm("return_to"))

		ip := c.ClientIP()
		ua := c.Request.UserAgent()
		var ipPtr, uaPtr *string
		if ip != "" {
			ipPtr = &ip
		}
		if ua != "" {
			uaPtr = &ua
		}

		result, err := deps.LocalLogin.Login(c.Request.Context(), service.LoginInput{
			Email:      email,
			Password:   password,
			TOTPCode:   totp,
			RememberMe: remember,
			IPAddress:  ipPtr,
			UserAgent:  uaPtr,
		})
		if err != nil {
			if errors.Is(err, service.ErrLoginRiskBackendUnavailable) {
				// Fail-CLOSED: the brute-force lockout backend was
				// unreachable, so the login is refused. 503 reveals ONLY
				// backend state (the password gate runs Check before any
				// user lookup), never account state.
				c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
				return
			}
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user_session.browser_login.failure",
				Outcome:   "denied",
				IPAddress: ip,
				UserAgent: ua,
			})
			// Re-render the form with a generic error code. Keep
			// `return_to` so the user can re-enter credentials and
			// resume.
			loc := "/api/v1/auth/browser-login?error=invalid_credentials"
			if returnTo != "" {
				loc += "&return_to=" + url.QueryEscape(returnTo)
			}
			c.Redirect(http.StatusSeeOther, loc)
			return
		}

		cookieValue := result.RefreshToken
		if deps.BrowserTokens != nil {
			ipStr, uaStr := "", ""
			if ipPtr != nil {
				ipStr = *ipPtr
			}
			if uaPtr != nil {
				uaStr = *uaPtr
			}
			var orgPtr *uuid.UUID
			if result.User != nil && result.User.OrganizationID != (uuid.UUID{}) {
				cp := result.User.OrganizationID
				orgPtr = &cp
			}
			issued, btErr := deps.BrowserTokens.Issue(c.Request.Context(), service.IssueBrowserSessionTokenInput{
				SessionID:      result.Session.ID,
				UserID:         result.Session.UserID,
				OrganizationID: orgPtr,
				UserAgent:      uaStr,
				IPAddress:      ipStr,
				ExpiresAt:      result.Session.ExpiresAt,
			})
			if btErr != nil || issued == nil {
				// FAIL CLOSED (P2-8). With BrowserTokens wired, the cookie
				// MUST be the opaque browser-session token — the raw
				// refresh token does NOT resolve as a session cookie. The
				// prior silent fall-through (cookieValue stayed
				// result.RefreshToken) redirected the user "logged in" with
				// a cookie that authenticates nothing, so every subsequent
				// request 401s. Refuse instead of that broken success.
				//
				// Response mirrors the ErrLoginRiskBackendUnavailable 503
				// posture above: a distinct, NON-credential signal so the
				// user is not falsely told their (correct) password was
				// wrong (the re-rendered form banner always reads "check
				// your credentials", so a redirect-to-form would mislead).
				// Server-side + account-independent → no enumeration.
				//
				// Non-goal (documented): LocalLogin already created the
				// session; we deliberately do NOT revoke it here (out of
				// scope). It expires naturally at result.Session.ExpiresAt.
				_ = deps.Audit.Record(c.Request.Context(), audit.Event{
					Action:    "user_session.browser_login.failure",
					Outcome:   "error",
					IPAddress: ip,
					UserAgent: ua,
					Metadata: map[string]any{
						"reason":     "browser_session_token_issue_failed",
						"session_id": result.Session.ID.String(),
					},
				})
				c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
				return
			}
			cookieValue = issued.Token
		}
		cookie := deps.CookieSession.Issue(cookieValue, result.Session.ExpiresAt)
		writeSessionCookie(c, cookie)

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.browser_login.success",
			Outcome:   "success",
			IPAddress: ip,
			UserAgent: ua,
			Metadata: map[string]any{
				"user_id":    result.UserID,
				"session_id": result.Session.ID.String(),
			},
		})

		if returnTo == "" {
			returnTo = "/"
		}
		c.Redirect(http.StatusSeeOther, returnTo)
	}
}

// validateReturnTo enforces the same-origin-path-only policy on the
// return_to parameter. Allowed: relative paths starting with "/" but
// NOT "//" (which is a protocol-relative URL).
//
// Anything else is rejected by returning "" — the caller defaults to
// "/" so the user still lands somewhere sensible.
func validateReturnTo(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "/") {
		return ""
	}
	if strings.HasPrefix(s, "//") {
		return ""
	}
	// Reject embedded CR/LF — header-injection defence.
	if strings.ContainsAny(s, "\r\n") {
		return ""
	}
	return s
}

// loginFormTemplate is the minimal HTML the browser receives. No
// CSS, no JS, no remote assets — the smallest credible login UI
// that demonstrates the cookie flow end-to-end. Operators with a
// branded SPA continue to drive the JSON `/api/v1/auth/login`
// endpoint and set the cookie themselves via the
// `/api/v1/auth/session/cookie-bind` (TODO future slice).
const loginFormTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>Sign in — Identuum</title>
</head>
<body>
  <main>
    <h1>Sign in</h1>
    {{ERROR}}
    <form method="POST" action="/api/v1/auth/browser-login" autocomplete="off">
      <label>Email <input type="email" name="email" required autofocus></label><br>
      <label>Password <input type="password" name="password" required></label><br>
      <label>TOTP (if enabled) <input type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code"></label><br>
      <label><input type="checkbox" name="remember_me" value="1"> Remember me</label><br>
      <input type="hidden" name="return_to" value="{{RETURN_TO}}">
      {{CSRF}}
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>`

// renderLoginForm writes the HTML form with the supplied return_to
// inserted as a hidden field and the error code rendered as a small
// banner. The values are HTML-escaped to defeat injection — neither
// is ever rendered raw.
func renderLoginForm(w http.ResponseWriter, returnTo, errCode, csrfToken string) {
	body := strings.ReplaceAll(loginFormTemplate, "{{RETURN_TO}}", html.EscapeString(returnTo))
	if errCode != "" {
		banner := `<p role="alert" data-error="` + html.EscapeString(errCode) + `">Sign-in failed. Please check your credentials and try again.</p>`
		body = strings.ReplaceAll(body, "{{ERROR}}", banner)
	} else {
		body = strings.ReplaceAll(body, "{{ERROR}}", "")
	}
	csrfInput := ""
	if csrfToken != "" {
		csrfInput = `<input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `">`
	}
	body = strings.ReplaceAll(body, "{{CSRF}}", csrfInput)
	_, _ = w.Write([]byte(body))
}

// readCSRFCookie returns the value of the named cookie, or "" if
// absent.
func readCSRFCookie(r *http.Request, name string) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}
