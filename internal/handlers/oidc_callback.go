package handlers

import (
	"context"
	"errors"
	"net/http"

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
// wired the callback also writes the two cookies POST /api/v1/auth/login
// writes, through the same issuance (IssueForSession) and the same writer
// (setAuthCookies), so the session has exactly a password sign-in's refresh,
// logout and revocation. Nil keeps the browser-session cookie alone.
type OIDCCallbackHandlerDeps struct {
	OIDCCallback  OIDCCallbackHandler
	CookieSession *service.CookieSessionService
	BrowserTokens *service.BrowserSessionTokenService
	UserToken     *service.UserTokenService
	Audit         audit.Service
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
	// docgen:summary=Complete upstream single-provider OIDC login: consume the one-time state, exchange the code for tokens, strictly validate the ID token against the provider JWKS, JIT-provision or match the local user, mint a local session, and 302-redirect to the stored return URL with the session cookies set (the browser-session cookie and, as a password sign-in, the console's access_token and refresh_token cookies).
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Anonymous. Consumes the OIDCState once (SELECT..FOR UPDATE + delete — replay fails). Strict ID-token validation (signature vs provider JWKS by kid, https-only + SSRF-guarded; rejects alg=none / alg-confusion; iss==provider issuer; aud==client_id; exp/nbf; nonce==stored). On success it applies the email_domains allow-list gate, JIT-provisions or matches the local user, mints a local session (same issuance path as password login; ACR derived from the upstream acr), sets the session cookie, and 302-redirects to the return URL stored at login-initiation (already sanitized — the provider response is never used to derive the target; empty ⇒ a safe default). A provider error, or a missing/expired/mismatched state, returns 4xx; a discovery/exchange failure returns 502; a validation failure returns 401; an off-allow-list / unverified / bound-email identity returns 403; a provisioning or session-mint failure returns 500. No token, code, or secret is ever logged or echoed.
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

		// Login complete — set the session cookie (REUSE the browser-login tail:
		// optional browser-session-token indirection, then CookieSession.Issue)
		// and 302-redirect to the STORED, already-sanitized ReturnURL.
		cookieValue := res.RefreshToken
		if deps.BrowserTokens != nil {
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
			if btErr == nil && issued != nil {
				cookieValue = issued.Token
			}
		}
		// A sign-in through an upstream provider offers no "remember me", so
		// the cookie ends with the browser session.
		writeSessionCookie(c, deps.CookieSession.IssueForSignIn(cookieValue, res.Session.ExpiresAt, false))
		clearUpstreamLoginBinding(c, state)

		// The console's session (F-1, V4-025): the same access_token and
		// refresh_token cookies the password login sets, from the same
		// session, through the same minting and the same writer. No
		// "remember me" here either, so the refresh cookie ends with the
		// browser session. A mint failure omits only the access cookie, as
		// the password login's response then omits the access token: the
		// refresh cookie still lets /bff/session/refresh mint one.
		if deps.UserToken != nil && res.User != nil {
			accessToken := ""
			if access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), res.User, res.Session); accessErr == nil && access != nil {
				accessToken = access.AccessToken
			}
			setAuthCookies(c, accessToken, res.RefreshToken, false)
		}

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
