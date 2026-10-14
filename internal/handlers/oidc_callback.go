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
	// docgen:notes=Anonymous. Consumes the OIDCState once (SELECT..FOR UPDATE + delete — replay fails). Strict ID-token validation (signature vs provider JWKS by kid, https-only + SSRF-guarded; rejects alg=none / alg-confusion; iss==provider issuer; aud==client_id; exp/nbf; nonce==stored). On success it applies the email_domains allow-list gate, JIT-provisions or matches the local user, mints a local session (same issuance path as password login; ACR derived from the upstream acr), mints every credential of the ONE family the sign-in's purpose names before writing any cookie (console sign-in never signs in to an application and the two sign-outs never end each other's session), and 302-redirects to the return URL stored at login-initiation (already sanitized — the provider response is never used to derive the target; empty ⇒ a safe default). Every refusal (v0.9.13, Q-A1) is a 302 to the console sign-in page /login?reason=<code> with no cookie and Cache-Control no-store, never a JSON body, and the code is one of a closed list: sign_in_failed (provider error, malformed provider id, ID-token validation failure), sign_in_expired (missing/expired/used state or code, or a browser that did not start the sign-in), sign_in_not_permitted (off-allow-list / unverified / bound-email identity, an administrator, an organization policy), email_not_shared (the provider shared no email in the ID token or userinfo), invitation_pending (an invitation not yet accepted), registration_pending (a self-registration awaiting approval), provider_unavailable (discovery or token exchange failed), sign_in_unavailable (provisioning, session mint, or a browser-session token or console access token that cannot be minted; the created session is revoked). When the ID token lacks email or email_verified and discovery names a userinfo_endpoint, userinfo is read with the upstream access token and fills only the missing claims when its sub equals the ID token's. No token, code, or secret is ever logged or echoed.
	router.GET("/api/v1/auth/idp/:id/callback", HandleOIDCCallback(deps))
}

// HandleOIDCCallback runs the callback via the service and maps outcomes to
// clean statuses. Nothing sensitive is ever written to the response or logs.
func HandleOIDCCallback(deps OIDCCallbackHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Every refusal is a redirect to the console sign-in page with a
		// reason code from a closed list (Q-A1 (a)): this is a page load.
		providerID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			redirectUpstreamRefusal(c, refusalSignInFailed)
			return
		}
		// A provider-reported error (e.g. user denied consent) → login failed.
		if c.Query("error") != "" {
			redirectUpstreamRefusal(c, refusalSignInFailed)
			return
		}
		state := c.Query("state")
		code := c.Query("code")
		if state == "" || code == "" {
			redirectUpstreamRefusal(c, refusalSignInExpired)
			return
		}
		// The sign-in must finish in the browser that started it: a callback
		// without the cookie planted at initiation (a link handed to someone
		// else) is refused before the state is consumed.
		if !upstreamLoginBound(c, state) {
			redirectUpstreamRefusal(c, refusalSignInExpired)
			return
		}

		ip := c.ClientIP()
		ua := c.Request.UserAgent()
		res, err := deps.OIDCCallback.HandleCallback(c.Request.Context(), providerID, state, code, ip, ua)
		if err != nil {
			// D-017 / G2 (OSS-0914-MUSTCHANGE): the member owes a password
			// change, or the admin-set password expired. No session exists;
			// the row names the member, the method and the provider, as the
			// password sign-in's row names the member.
			if res != nil && res.User != nil {
				step := &service.LoginResult{User: res.User}
				meta := map[string]any{"method": "oidc_upstream", "provider_id": providerID.String()}
				if errors.Is(err, service.ErrLoginPasswordExpired) {
					auditLoginStep(c, deps.Audit, "user_session.login.password_expired", step, meta)
				} else {
					auditLoginStep(c, deps.Audit, "user_session.login.password_change_required", step, meta)
				}
			}
			redirectUpstreamRefusal(c, upstreamRefusalReason(err))
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

// The reason codes a refused upstream sign-in carries to the console sign-in
// page, /login?reason=<code> (Q-A1 (a), owner 2026-10-13). The callback is a
// top-level browser navigation, so a refusal never answers raw JSON; the
// console shows plain words for each code. The list is CLOSED: the callback
// sends no other value, and docs/guides/oidc-upstream-login.md ("When the
// sign-in is refused") documents the same set.
const (
	// refusalSignInFailed: the provider reported an error, the provider id is
	// malformed, or the provider's ID token failed validation.
	refusalSignInFailed = "sign_in_failed"
	// refusalSignInExpired: the sign-in state is missing, expired, already
	// used, or the callback reached a browser that did not start the sign-in.
	refusalSignInExpired = "sign_in_expired"
	// refusalSignInNotPermitted: the identity may not sign in here (an
	// unverified or off-list address, an administrator, an address bound to
	// another identity, an organization policy).
	refusalSignInNotPermitted = "sign_in_not_permitted"
	// refusalEmailNotShared: the provider shared no email address (D7).
	refusalEmailNotShared = "email_not_shared"
	// refusalInvitationPending: the person has an invitation not yet
	// accepted (O19).
	refusalInvitationPending = "invitation_pending"
	// refusalRegistrationPending: the person's self-registration waits for
	// an administrator's approval (O19).
	refusalRegistrationPending = "registration_pending"
	// refusalProviderUnavailable: the provider's discovery or token
	// endpoint could not be used.
	refusalProviderUnavailable = "provider_unavailable"
	// refusalSignInUnavailable: the sign-in could not be completed on this
	// side (a store or key failure); trying again may work.
	refusalSignInUnavailable = "sign_in_unavailable"
	// refusalPasswordChangeRequired: the member must first choose a new
	// password, as an administrator asked (D-017); password sign-in leads to
	// the change step (OSS-0914-MUSTCHANGE).
	refusalPasswordChangeRequired = "password_change_required"
	// refusalPasswordExpired: the member's administrator-set password is past
	// its 24 hours (G2); the member asks the administrator for a reset link.
	refusalPasswordExpired = "password_expired"
)

// UpstreamSignInRefusalReasons is the closed list of reason codes above.
var UpstreamSignInRefusalReasons = []string{
	refusalSignInFailed,
	refusalSignInExpired,
	refusalSignInNotPermitted,
	refusalEmailNotShared,
	refusalInvitationPending,
	refusalRegistrationPending,
	refusalProviderUnavailable,
	refusalSignInUnavailable,
	refusalPasswordChangeRequired,
	refusalPasswordExpired,
}

// consoleSignInPath is the console's sign-in page; its reason banner reads
// the code (identuum-ui).
const consoleSignInPath = "/login"

// redirectUpstreamRefusal answers a refused upstream sign-in: 302 to the
// console sign-in page with the reason code, no cookie, not cached.
func redirectUpstreamRefusal(c *gin.Context, reason string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Redirect(http.StatusFound, consoleSignInPath+"?reason="+url.QueryEscape(reason))
}

// upstreamRefusalReason maps a callback service error to its reason code.
// The specific O19 and D7 cases are tested before the ErrCallbackForbidden
// they wrap.
func upstreamRefusalReason(err error) string {
	switch {
	case errors.Is(err, service.ErrCallbackValidationFailed):
		return refusalSignInFailed
	case errors.Is(err, service.ErrLoginPasswordChangeRequired):
		return refusalPasswordChangeRequired
	case errors.Is(err, service.ErrLoginPasswordExpired):
		return refusalPasswordExpired
	case errors.Is(err, service.ErrCallbackInvitePending):
		return refusalInvitationPending
	case errors.Is(err, service.ErrCallbackRegistrationPending):
		return refusalRegistrationPending
	case errors.Is(err, service.ErrCallbackEmailNotShared):
		return refusalEmailNotShared
	case errors.Is(err, service.ErrCallbackForbidden):
		return refusalSignInNotPermitted
	case errors.Is(err, service.ErrCallbackProvisionFailed), errors.Is(err, service.ErrCallbackSessionFailed):
		return refusalSignInUnavailable
	case errors.Is(err, service.ErrCallbackDiscoveryFailed), errors.Is(err, service.ErrCallbackExchangeFailed):
		return refusalProviderUnavailable
	default: // ErrCallbackStateInvalid
		return refusalSignInExpired
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
// after the callback service minted its session: no cookie of any kind, and
// the console sign-in page with reason sign_in_unavailable (Q-A1 (a); until
// v0.9.13 the browser login's 503 text). It attempts to revoke the session the
// callback service created, so a refused sign-in normally leaves nothing live
// (OSS-HARDENING-2 item 2); a store outage can make that attempt fail, and
// the audit names the reason and says whether the revocation happened. The
// refusal stands either way: no credential is delivered.
func refuseUpstreamSignIn(c *gin.Context, deps OIDCCallbackHandlerDeps, res *service.OIDCCallbackResult, providerID uuid.UUID, ip, ua, reason string) {
	revoked := false
	if deps.UserSession != nil {
		revoked = deps.UserSession.RevokeSession(c.Request.Context(), res.Session.ID, reason) == nil
	}
	event := audit.Event{
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
	}
	if res.User != nil {
		event.OrganizationID = res.User.OrganizationID
	}
	_ = deps.Audit.Record(c.Request.Context(), event)
	redirectUpstreamRefusal(c, refusalSignInUnavailable)
}
