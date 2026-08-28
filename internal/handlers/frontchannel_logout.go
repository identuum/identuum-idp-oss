package handlers

import (
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// FrontchannelLogoutHandlerDeps wires the OIDC Front-Channel
// Logout 1.0 endpoint.
//
// CookieSession + UserSession required. Clients + Issuer are
// optional — when both present AND the request carries a
// `client_id` query parameter, the handler renders an iframe
// pointing at the registered RP's `frontchannel_logout_uri` so
// the RP can clear its own state in the same browsing context.
type FrontchannelLogoutHandlerDeps struct {
	CookieSession *service.CookieSessionService
	UserSession   *service.UserSessionService
	// Clients resolves a `client_id` query parameter to a
	// *domain.Client whose FrontchannelLogoutURI is used as the
	// iframe src. nil disables iframe rendering — the handler
	// falls back to the minimal "you are signed out" body.
	Clients ConsentClientLookup
	// Issuer is appended as `?iss=<issuer>` on the iframe URL
	// when client.FrontchannelLogoutSessionRequired is true.
	// Empty issuer disables iss emission.
	Issuer string
	Audit  audit.Service
}

// RegisterFrontchannelLogoutRoutes mounts
//
//	GET /api/v1/oidc/frontchannel-logout
//
// onto router. Registers only when both deps are wired.
func RegisterFrontchannelLogoutRoutes(router gin.IRouter, deps FrontchannelLogoutHandlerDeps) {
	if deps.CookieSession == nil || deps.UserSession == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=oidc
	// docgen:method=GET
	// docgen:path=/api/v1/oidc/frontchannel-logout
	// docgen:summary=OIDC Front-Channel Logout 1.0 iframe endpoint (clears the browser cookie + revokes the cookie-resolved session, then renders a minimal iframe-safe HTML response).
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Iframe target — anonymous by design. The route accepts cookies but does not require them; an unauthenticated hit renders the same iframe-safe stub.
	router.GET("/api/v1/oidc/frontchannel-logout", HandleFrontchannelLogout(deps))
}

// HandleFrontchannelLogout clears the browser cookie + revokes the
// cookie-resolved session, then renders a minimal iframe-safe HTML
// page. The page carries no JS, no remote assets, and no cross-
// origin POSTs — Front-Channel Logout 1.0 §3 prescribes a passive
// page that simply lets the RP know the OP-side logout is done.
//
// The page sets `Cache-Control: no-store` so a back button does not
// resurrect a logged-out view.
func HandleFrontchannelLogout(deps FrontchannelLogoutHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var resolvedSession uuid.UUID
		if cookieVal, ok := deps.CookieSession.Read(c.Request); ok {
			if resolved, err := deps.CookieSession.Resolve(c.Request.Context(), cookieVal); err == nil && resolved != nil && resolved.Session != nil {
				resolvedSession = resolved.Session.ID
				_ = deps.UserSession.RevokeSession(c.Request.Context(), resolved.Session.ID, "frontchannel_logout")
				_ = deps.Audit.Record(c.Request.Context(), audit.Event{
					Action:    "user_session.frontchannel_logout",
					Outcome:   "success",
					IPAddress: c.ClientIP(),
					UserAgent: c.Request.UserAgent(),
					Metadata: map[string]any{
						"session_id": resolved.Session.ID.String(),
					},
				})
			}
		}
		writeSessionCookie(c, deps.CookieSession.Clear())

		// Optional iframe rendering. When the request carries a
		// `client_id` AND we can resolve it to a client whose
		// `frontchannel_logout_uri` is populated, we render an
		// iframe pointing at that URI so the RP can clear its own
		// state. Per OIDC Front-Channel Logout 1.0 §3, when
		// `frontchannel_logout_session_required` is true, we
		// append `iss=<issuer>` and `sid=<session_id>` to the URI.
		var iframeSrc string
		clientID := strings.TrimSpace(c.Query("client_id"))
		if deps.Clients != nil && clientID != "" {
			if client, err := deps.Clients.GetClientByClientID(c.Request.Context(), clientID); err == nil && client != nil {
				iframeSrc = resolveFrontchannelIframeSrc(client, deps.Issuer, resolvedSession)
			}
		}

		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		if iframeSrc == "" {
			// No iframe to render — fall back to the minimal
			// "signed out" body with the locked-down CSP from
			// the prior slice.
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
			c.String(http.StatusOK, frontchannelLogoutHTML)
			return
		}
		// Iframe variant: scope `frame-src` to the iframe origin
		// only so a future template change can't accidentally pull
		// in a third-party origin.
		origin := iframeOrigin(iframeSrc)
		csp := "default-src 'none'; style-src 'unsafe-inline'"
		if origin != "" {
			csp += "; frame-src " + origin
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Security-Policy", csp)
		c.String(http.StatusOK, renderFrontchannelIframe(iframeSrc))
	}
}

// resolveFrontchannelIframeSrc returns the URL to embed in the
// iframe, or "" when:
//
//   - client.FrontchannelLogoutURI is empty,
//   - the URI is not parseable / fails ValidateLogoutURI, OR
//   - client.FrontchannelLogoutSessionRequired is true but neither
//     issuer nor a resolved session is available (we MUST NOT
//     leak unregistered data into the iframe URL).
func resolveFrontchannelIframeSrc(client *domain.Client, issuer string, sessionID uuid.UUID) string {
	if client == nil || client.FrontchannelLogoutURI == "" {
		return ""
	}
	if err := domain.ValidateLogoutURI(client.FrontchannelLogoutURI); err != nil {
		return ""
	}
	u, err := url.Parse(client.FrontchannelLogoutURI)
	if err != nil {
		return ""
	}
	if client.FrontchannelLogoutSessionRequired {
		if issuer == "" || sessionID == (uuid.UUID{}) {
			// Spec-compliant fallback: a frontchannel iframe
			// without iss + sid is meaningless to the RP. Skip
			// iframe rendering entirely rather than leak a
			// half-populated URL.
			return ""
		}
		q := u.Query()
		q.Set("iss", issuer)
		q.Set("sid", sessionID.String())
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// iframeOrigin returns the scheme://host[:port] of the iframe URL.
// Returns "" on parse failure (CSP falls back to the safer
// no-frame-src default).
func iframeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// renderFrontchannelIframe returns the iframe-flavoured HTML body
// with the supplied URL escaped into the src attribute.
func renderFrontchannelIframe(src string) string {
	return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-store">
<title>Logging out</title>
<style>body{font-family:system-ui,sans-serif;margin:1em;color:#333} iframe{border:0;width:1px;height:1px;visibility:hidden}</style>
</head><body>
<p>Signing you out of all sessions...</p>
<iframe src="` + html.EscapeString(src) + `" sandbox="allow-same-origin"></iframe>
</body></html>`
}

// frontchannelLogoutHTML is the minimal "you are logged out" body
// served inside the RP's logout iframe.
const frontchannelLogoutHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-store">
<title>Logged out</title>
<style>body{font-family:system-ui,sans-serif;margin:1em;color:#333}</style>
</head><body>
<p>You have been signed out.</p>
</body></html>`
