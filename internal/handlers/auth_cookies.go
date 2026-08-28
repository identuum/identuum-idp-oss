package handlers

// auth_cookies.go — OSS port of the monolith's auth-cookie contract.
//
// Why this exists:
//   The OSS local-login handler previously returned a JSON body but set
//   NO cookies. identuum-ui's server-session helper expects the IdP to
//   set `access_token` and (optionally) `refresh_token` HttpOnly cookies
//   on the login response, and to accept the `access_token` cookie on
//   subsequent calls to GET /api/v1/validate. Without the Set-Cookie
//   headers the browser never carries credentials forward and every
//   protected page redirects to /login?reason=session_expired.
//
// Contract source: identuum-idp/internal/handlers/handler_auth_cookies.go.
// This is a behaviour-compatible port — same cookie names, same
// HttpOnly/Lax/Path posture, same localhost-aware Secure flag, same
// MaxAge constants. We do NOT import any old-monolith code; only the
// observable wire shape is preserved.
//
// Cookie attributes (LOCK these — UI middleware reads them by name +
// expects these exact properties):
//
//   - Name:     access_token          / refresh_token
//   - Path:     "/"
//   - HttpOnly: true                  (browser JS cannot read the value)
//   - SameSite: Lax                   (per ARCHITECTURAL_GUIDELINES §7 —
//                                      same as monolith)
//   - Secure:   runtime-conditional   (false on localhost so the local-
//                                      demo HTTP runtime works; true on
//                                      release-mode non-localhost)
//   - MaxAge:   accessTokenCookieMaxAgeSec / refreshTokenCookieMaxAgeSec
//               (refresh MaxAge=0 when !rememberMe so it's a session
//                cookie that vanishes on browser close)
//
// Strict no-secret-leak rule: the cookie values are forwarded verbatim
// from the issued tokens; this file never logs them.

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// accessTokenCookieMaxAgeSec mirrors the monolith's 900-second access-
// token cookie MaxAge. Matches the default UserTokenService.AccessTokenTTL
// of 1h at the token-validity layer; the cookie is shorter so the browser
// proactively re-asks for a refresh before the token's `exp`.
const accessTokenCookieMaxAgeSec = 900

// refreshTokenCookieMaxAgeSec mirrors the monolith's 7-day refresh-token
// cookie MaxAge when rememberMe is true. When rememberMe is false the
// cookie becomes a session cookie (MaxAge=0 — discarded on browser close).
const refreshTokenCookieMaxAgeSec = 604800

// setAuthCookies writes the two browser cookies the UI consumes after a
// successful login. accessToken is REQUIRED; refreshToken may be empty
// (in which case the refresh_token cookie is not written — preserves the
// "access-only" wire shape for callers that have not enabled the refresh
// pathway).
//
// rememberMe maps to the refresh_token cookie's MaxAge per the monolith
// convention: true → 7-day persistent cookie, false → session cookie.
// The access_token cookie always uses the 15-minute MaxAge regardless
// of rememberMe.
func setAuthCookies(c *gin.Context, accessToken, refreshToken string, rememberMe bool) {
	secure := cookieSecureForRequest(c.Request)
	// Access token cookie — always set when a token is supplied.
	if accessToken != "" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			MaxAge:   accessTokenCookieMaxAgeSec,
			Path:     "/",
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	// Refresh token cookie — only set when supplied.
	if refreshToken != "" {
		refreshMax := refreshTokenCookieMaxAgeSec
		if !rememberMe {
			refreshMax = 0
		}
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			MaxAge:   refreshMax,
			Path:     "/",
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// clearAuthCookies expires both cookies in the browser. Must be called
// on logout so that HttpOnly cookies (which JS cannot delete) are
// removed immediately rather than waiting for their natural MaxAge to
// elapse.
func clearAuthCookies(c *gin.Context) {
	secure := cookieSecureForRequest(c.Request)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// cookieSecureForRequest mirrors the monolith's runtime-resolved Secure
// flag. The bool is true when Gin is in release mode AND the request's
// Host is not a localhost/loopback name. This keeps the local-demo
// HTTP runtime usable (browser would otherwise drop a Secure cookie on
// a plain http://localhost origin) while making release deployments
// fail-closed on non-HTTPS hosts.
func cookieSecureForRequest(r *http.Request) bool {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	isLocalhost := host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "host.docker.internal"
	return gin.Mode() == gin.ReleaseMode && !isLocalhost
}

// writeBrowserCSRFCookie stamps the transport-correct Secure flag onto a CSRF
// cookie produced by BrowserCSRFService and writes it. The service leaves
// Secure=false because it cannot see the request; this upgrades it to true in
// production (ReleaseMode, non-localhost) via the SAME cookieSecureForRequest
// the auth session cookies use, so the double-submit cookie returns over
// http://localhost (the local-dev form) while staying https-only in production
// (BROWSER-LOGIN-PLAINHTTP-1).
func writeBrowserCSRFCookie(c *gin.Context, cookie *http.Cookie) {
	cookie.Secure = cookieSecureForRequest(c.Request)
	http.SetCookie(c.Writer, cookie)
}

// writeSessionCookie stamps the transport-correct Secure flag onto the
// identuum_session cookie produced by CookieSessionService.Issue/Clear and
// writes it. The service bakes a fail-safe Secure=true default (it cannot see
// the request, and the runtime leaves AllowPlainHTTP unset), which never
// returns over http://localhost — so the browser-login session the interactive
// /oauth/consent flow depends on was unreachable on the plain-HTTP appliance,
// exactly as the CSRF cookie was (BROWSER-LOGIN-PLAINHTTP-1). This upgrades the
// Secure flag to the request-adaptive value — the SAME cookieSecureForRequest
// the auth and CSRF cookies use — so the session returns over http://localhost
// while staying https-only in production. Issue and Clear both route through
// here so the delete-cookie's flags match the planted cookie's.
func writeSessionCookie(c *gin.Context, cookie *http.Cookie) {
	cookie.Secure = cookieSecureForRequest(c.Request)
	http.SetCookie(c.Writer, cookie)
}
