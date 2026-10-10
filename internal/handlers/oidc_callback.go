package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OIDCCallbackHandler is the narrow callback seam the handler consumes.
// *service.OIDCCallbackService satisfies it. It completes login and returns the
// material the handler needs to set the session cookie and redirect: the
// resolved local user, the minted session, its refresh token, and the stored,
// already-sanitized ReturnURL.
type OIDCCallbackHandler interface {
	HandleCallback(ctx context.Context, providerID uuid.UUID, state, code, ipAddress, userAgent string) (*service.OIDCCallbackResult, error)
}

// OIDCCallbackHandlerDeps wires the always-public upstream-OIDC callback
// endpoint (OSS basic single-provider login — docs/design/oss-basic-oidc-login.md).
//
// OIDCCallback and CookieSession are REQUIRED — when either is nil the route is
// simply absent (optional feature, no fault). BrowserTokens is OPTIONAL: when
// wired, the session cookie carries an opaque browser-session token instead of
// the raw refresh token (same indirection as browser login). This endpoint
// completes login: it mints a session, sets the cookies, and 302-redirects to
// the stored sanitized ReturnURL.
//
// UserToken is OPTIONAL and is what the console needs (OSS-UPSTREAM-CONSOLE-
// SESSION, test-book V4-025, finding F-1 of TESTBOOK-FIXTURES-1): the console
// validates the access_token cookie its /bff boundary lifts into a Bearer,
// never the browser-session cookie, so a callback that set only
// identuum_session returned the person to /login signed out. With UserToken
// wired, a sign-in started FROM THE CONSOLE writes the two cookies
// POST /api/v1/auth/login writes, through the same issuance (IssueForSession)
// and the same writer (setAuthCookies), so the session has exactly a password
// sign-in's refresh, logout and revocation — and NOT the browser-session
// cookie: a console sign-in never signs in to an application (D-023; review
// finding F5). A sign-in started for an application's /authorize writes the
// browser-session cookie alone (upstreamSignInPurpose). Nil UserToken keeps
// the browser-session cookie alone for every sign-in.
type OIDCCallbackHandlerDeps struct {
	OIDCCallback  OIDCCallbackHandler
	CookieSession *service.CookieSessionService
	BrowserTokens *service.BrowserSessionTokenService
	UserToken     *service.UserTokenService
	// UserSession revokes the session the callback service created when the
	// sign-in cannot complete (the browser-session token did not issue), so a
	// refused sign-in leaves no live session behind. Nil leaves that session
	// to expire on its own; the refusal's audit says which happened.
	UserSession *service.UserSessionService
	Audit       audit.Service
}

// RegisterOIDCCallbackRoutes mounts
//
//	GET /api/v1/auth/idp/:id/callback   (public)
//
// onto router. Nil OIDCCallback OR nil CookieSession ⇒ the route is not mounted
// (login cannot complete without the cookie tail).
func RegisterOIDCCallbackRoutes(router gin.IRouter, deps OIDCCallbackHandlerDeps) {
	if deps.OIDCCallback == nil || deps.CookieSession == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// docgen:endpoint
	// docgen:surface=oidc-login
	// docgen:method=GET
	// docgen:path=/api/v1/auth/idp/:id/callback
	// docgen:summary=Complete upstream single-provider OIDC login: consume the one-time state, exchange the code for tokens, strictly validate the ID token against the provider JWKS, JIT-provision or match the local user, mint a local session, and 302-redirect to the stored return URL with ONE credential family set: for a sign-in started from the console, the console's access_token and refresh_token cookies as a password sign-in sets them; for a sign-in started for an application's /authorize (a return URL at the authorize endpoint), the IdP's own browser-session cookie.
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Anonymous. Consumes the OIDCState once (SELECT..FOR UPDATE + delete — replay fails). Strict ID-token validation (signature vs provider JWKS by kid, https-only + SSRF-guarded; rejects alg=none / alg-confusion; iss==provider issuer; aud==client_id; exp/nbf; nonce==stored). On success it applies the email_domains allow-list gate, JIT-provisions or matches the local user, mints a local session (same issuance path as password login; ACR derived from the upstream acr), mints every credential of the ONE family the sign-in's purpose names before writing any cookie (console sign-in never signs in to an application and the two sign-outs never end each other's session), and 302-redirects to the return URL stored at login-initiation (already sanitized — the provider response is never used to derive the target; empty ⇒ a safe default). A provider error, or a missing/expired/mismatched state, returns 4xx; a discovery/exchange failure returns 502; a validation failure returns 401; an off-allow-list / unverified / bound-email identity returns 403; a provisioning or session-mint failure returns 500; a browser-session token or console access token that cannot be minted returns 503 with no cookie and the created session revoked. No token, code, or secret is ever logged or echoed.
	router.GET("/api/v1/auth/idp/:id/callback", HandleOIDCCallback(deps))
}

// HandleOIDCCallback runs the callback via the service and maps outcomes to
// clean statuses. Nothing sensitive is ever written to the response or logs.
func HandleOIDCCallback(deps OIDCCallbackHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		providerID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
			return
		}
		// A provider-reported error (e.g. user denied consent) → login failed.
		if c.Query("error") != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "login failed"})
			return
		}
		state := c.Query("state")
		code := c.Query("code")
		if state == "" || code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing state or code"})
			return
		}
		// The sign-in must finish in the browser that started it: a callback
		// without the cookie planted at initiation (a link handed to someone
		// else) is refused before the state is consumed.
		if !upstreamLoginBound(c, state) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired login state"})
			return
		}

		ip := c.ClientIP()
		ua := c.Request.UserAgent()
		res, err := deps.OIDCCallback.HandleCallback(c.Request.Context(), providerID, state, code, ip, ua)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrCallbackValidationFailed):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
			case errors.Is(err, service.ErrCallbackForbidden):
				c.JSON(http.StatusForbidden, gin.H{"error": "login not permitted"})
			case errors.Is(err, service.ErrCallbackProvisionFailed), errors.Is(err, service.ErrCallbackSessionFailed):
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			case errors.Is(err, service.ErrCallbackDiscoveryFailed):
				c.JSON(http.StatusBadGateway, gin.H{"error": "upstream discovery failed"})
			case errors.Is(err, service.ErrCallbackExchangeFailed):
				c.JSON(http.StatusBadGateway, gin.H{"error": "upstream token exchange failed"})
			default: // ErrCallbackStateInvalid
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired login state"})
			}
			return
		}

		// Login complete. EVERY credential is minted before ANY cookie is
		// written (F2, OSS-REVIEW-FIXES-1): a sign-in is committed to the
		// browser whole or not at all. Until then a failed console mint
		// still planted the browser-session and refresh cookies and
		// redirected "signed in", which left a jar holding another user's
		// valid access cookie validating as that user while the audit said
		// this one had signed in.
		//
		// ONE credential family, chosen by what the sign-in was started for
		// (F5, D-023 preserved): a console sign-in gets the console's two
		// cookies, an application's sign-in the browser-session cookie the
		// resumed /authorize reads. An edition that mounts no console (no
		// UserToken) has only the browser-session family to give.
		purpose := upstreamSignInPurposeOf(res.ReturnURL)
		console := purpose == upstreamSignInForConsole && deps.UserToken != nil && res.User != nil

		// The browser-session cookie REUSES the browser-login tail: the
		// optional browser-session-token indirection, then CookieSession.Issue.
		cookieValue := res.RefreshToken
		if !console && deps.BrowserTokens != nil {
			var orgPtr *uuid.UUID
			if res.User != nil && res.User.OrganizationID != (uuid.UUID{}) {
				cp := res.User.OrganizationID
				orgPtr = &cp
			}
			issued, btErr := deps.BrowserTokens.Issue(c.Request.Context(), service.IssueBrowserSessionTokenInput{
				SessionID:      res.Session.ID,
				UserID:         res.Session.UserID,
				OrganizationID: orgPtr,
				UserAgent:      ua,
				IPAddress:      ip,
				ExpiresAt:      res.Session.ExpiresAt,
			})
			if btErr != nil || issued == nil {
				// FAIL CLOSED (P2-8, as finishBrowserSignIn): with
				// BrowserTokens wired the cookie MUST be the opaque token;
				// the raw refresh token resolves as no session, so the old
				// fall-through planted a cookie that authenticated nothing
				// and sent the person on "signed in" (OSS-HARDENING-2 item 2).
				refuseUpstreamSignIn(c, deps, res, providerID, ip, ua, "browser_session_token_issue_failed")
				return
			}
			cookieValue = issued.Token
		}
		// The console's session (F-1, V4-025): the same access_token and
		// refresh_token cookies the password login sets, from the same
		// session, through the same minting and the same writer. The access
		// token is minted here, before any cookie: a mint that fails (the
		// signing key cannot be read) refuses the sign-in exactly as the
		// browser-session token above does, instead of planting the refresh
		// cookie beside whatever access cookie the browser already holds.
		accessToken := ""
		if console {
			access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), res.User, res.Session)
			if accessErr != nil || access == nil || access.AccessToken == "" {
				refuseUpstreamSignIn(c, deps, res, providerID, ip, ua, "console_token_issue_failed")
				return
			}
			accessToken = access.AccessToken
		}

		// Everything minted: commit the sign-in to the browser. A sign-in
		// through an upstream provider offers no "remember me", so the
		// session cookie and the refresh cookie end with the browser session.
		if console {
			setAuthCookies(c, accessToken, res.RefreshToken, false)
		} else {
			writeSessionCookie(c, deps.CookieSession.IssueForSignIn(cookieValue, res.Session.ExpiresAt, false))
		}
		clearUpstreamLoginBinding(c, state)

		// Audited as a sign-in of the person and their organization (nobody
		// is in the request context yet, so the actor is set here): the
		// upstream event, and the one sign-in event every console sign-in
		// records, carrying the method so an auditor never reads it as a
		// password sign-in (OSS-UPSTREAM-CONSOLE-SESSION Q2, owner: yes).
		signedIn := audit.Event{
			Outcome:   "success",
			ActorType: audit.ActorTypeUser,
			ActorID:   res.Session.UserID,
			IPAddress: ip,
			UserAgent: ua,
		}
		if res.User != nil {
			signedIn.ActorEmail = res.User.Email
			signedIn.ActorRole = string(res.User.Role)
			signedIn.OrganizationID = res.User.OrganizationID
		}
		upstream := signedIn
		upstream.Action = "auth.oidc_login.success"
		upstream.Metadata = map[string]any{
			"provider_id": providerID.String(),
			"session_id":  res.Session.ID.String(),
		}
		_ = deps.Audit.Record(c.Request.Context(), upstream)
		signedIn.Action = "user_session.login.success"
		signedIn.Metadata = map[string]any{
			"user_id":     res.Session.UserID.String(),
			"session_id":  res.Session.ID.String(),
			"method":      "oidc_upstream",
			"provider_id": providerID.String(),
		}
		_ = deps.Audit.Record(c.Request.Context(), signedIn)

		returnTo := res.ReturnURL
		if returnTo == "" {
			returnTo = "/"
		}
		c.Redirect(http.StatusFound, returnTo)
	}
}

// upstreamSignInPurpose is what an upstream sign-in was started FOR, and so
// which ONE credential family its callback establishes (D-023: a console
// sign-in never signs in to an application, and the two sign-outs never end
// each other's session). The flow state carries it as the stored return URL:
// a sign-in that returns to the authorize endpoint is an application's
// sign-in; every other return (a console page) is the console's.
type upstreamSignInPurpose int

const (
	// upstreamSignInForConsole: the console's access_token and refresh_token
	// cookies, as POST /api/v1/auth/login sets them.
	upstreamSignInForConsole upstreamSignInPurpose = iota
	// upstreamSignInForApplication: the IdP's own browser-session cookie, as
	// the browser login sets it, so the resumed /authorize finds its principal.
	upstreamSignInForApplication
)

// authorizeEndpointPath is the OAuth/OIDC authorization endpoint's path, the
// one return URL that names an application's sign-in.
const authorizeEndpointPath = "/api/v1/oauth/authorize"

// upstreamSignInPurposeOf reads the purpose out of the stored, already
// sanitized return URL (a same-site relative path).
func upstreamSignInPurposeOf(returnURL string) upstreamSignInPurpose {
	u, err := url.Parse(returnURL)
	if err == nil && u.Path == authorizeEndpointPath {
		return upstreamSignInForApplication
	}
	return upstreamSignInForConsole
}

// refuseUpstreamSignIn is the one way a completed upstream sign-in is refused
// after the callback service minted its session: no cookie of any kind, no
// redirect, the browser login's 503 text (a non-credential signal; the
// provider did sign the person in). It attempts to revoke the session the
// callback service created, so a refused sign-in normally leaves nothing live
// (OSS-HARDENING-2 item 2); a store outage can make that attempt fail, and
// the audit names the reason and says whether the revocation happened. The
// refusal stands either way: no credential is delivered.
func refuseUpstreamSignIn(c *gin.Context, deps OIDCCallbackHandlerDeps, res *service.OIDCCallbackResult, providerID uuid.UUID, ip, ua, reason string) {
	revoked := false
	if deps.UserSession != nil {
		revoked = deps.UserSession.RevokeSession(c.Request.Context(), res.Session.ID, reason) == nil
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    "auth.oidc_login.failure",
		Outcome:   "error",
		IPAddress: ip,
		UserAgent: ua,
		Metadata: map[string]any{
			"reason":          reason,
			"provider_id":     providerID.String(),
			"session_id":      res.Session.ID.String(),
			"session_revoked": revoked,
		},
	})
	c.String(http.StatusServiceUnavailable, "temporarily unavailable, try again")
}
