package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// EndSessionHandlerDeps wires the OIDC RP-initiated logout
// endpoint (Core §5).
//
// CookieSession is REQUIRED; UserSession is REQUIRED. The Clients +
// IDTokenVerifier seams are OPTIONAL — without them the slice
// supports cookie-driven logout only.
type EndSessionHandlerDeps struct {
	CookieSession   *service.CookieSessionService
	UserSession     *service.UserSessionService
	Clients         ConsentClientLookup
	IDTokenVerifier *service.IDTokenVerifier
	// BackchannelDelivery posts the logout token to a relying party's
	// back-channel logout endpoint. *service.BackchannelLogoutService
	// satisfies it; nil disables back-channel delivery.
	BackchannelDelivery BackchannelDeliverer
	// SessionRPs names the relying parties that hold an ID token for a
	// session, so ending it can notify every one of them that registered a
	// back-channel endpoint, not only the one that asked. Nil notifies only the
	// client the request names.
	SessionRPs SessionRelyingParties
	// Background runs the deliveries after the response; nil runs them inline.
	Background    service.BackgroundRunner
	BrowserTokens *service.BrowserSessionTokenService
	Audit         audit.Service
}

// BackchannelDeliverer posts a logout token to one relying party.
type BackchannelDeliverer interface {
	Deliver(ctx context.Context, in service.DeliverInput) (*service.DeliverResult, error)
}

// SessionRelyingParties names the relying parties recorded for a session.
type SessionRelyingParties interface {
	ClientIDs(ctx context.Context, sessionID uuid.UUID) ([]string, error)
}

// RegisterEndSessionRoutes mounts GET /api/v1/oidc/logout. The
// route registers only when CookieSession + UserSession are both
// wired.
func RegisterEndSessionRoutes(router gin.IRouter, deps EndSessionHandlerDeps) {
	if deps.CookieSession == nil || deps.UserSession == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	// docgen:endpoint
	// docgen:surface=oidc
	// docgen:method=GET
	// docgen:path=/api/v1/oidc/logout
	// docgen:summary=OIDC RP-initiated logout / end_session endpoint (clears the browser cookie + revokes the cookie-resolved session; honours post_logout_redirect_uri when allowed by the registered client).
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Anonymous callers receive the same end-session UX (idempotent) — no session is required for the route to terminate cleanly. Terminal success is 200 with the IdP's "You are signed out" HTML page when no post_logout_redirect_uri is given (D-018a: Cache-Control no-store, a CSP of default-src 'none' with no scripts, naming no user or client), OR a 302 redirect to the validated post_logout_redirect_uri. A post_logout_redirect_uri whose client cannot be resolved still answers 204; one the client does not allow answers 400.
	router.GET("/api/v1/oidc/logout", HandleEndSession(deps))
}

// HandleEndSession implements the minimal safe end_session_endpoint:
//
//   - Clears the browser session cookie unconditionally.
//   - Revokes the user session bound to the cookie (when present).
//   - Validates `post_logout_redirect_uri` against the resolved
//     client's allowlist (when a client_id query parameter or a
//     resolved bearer principal lets us identify the client).
//   - Echoes `state` on the redirect.
//   - Falls back to a 204 No Content when no redirect_uri was
//     validated. The wire shape mirrors monolith's behavior of
//     silently no-redirect when validation fails.
//
// `id_token_hint` is verified before use — signature, kid, algorithm
// and issuer, with client_id required in `aud` — and an unverifiable
// hint is refused with invalid_request.
func HandleEndSession(deps EndSessionHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		state := c.Query("state")
		clientID := c.Query("client_id")
		postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
		idTokenHint := c.Query("id_token_hint")

		// Phase 0: verify id_token_hint (when wired + supplied).
		// Verification fails CLOSED — we return 400 before
		// clearing cookies so a malicious caller cannot tamper
		// with the logout to silently log out arbitrary users via
		// a forged hint. A verified hint may:
		//   - resolve a client_id from its `aud` claim (when no
		//     explicit client_id query param is set).
		//   - revoke a specific session via its `session_id` claim.
		//   - constrain the explicit client_id query param via the
		//     "if both, they must match" rule.
		var hint *service.VerifiedIDTokenHint
		if deps.IDTokenVerifier != nil && idTokenHint != "" {
			// An expired hint is accepted (RP-Initiated Logout 1.0 §2): the
			// signature and issuer are still verified.
			verified, err := deps.IDTokenVerifier.VerifyForLogout(c.Request.Context(), idTokenHint)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "id_token_hint is invalid",
				})
				return
			}
			hint = verified

			// When the caller ALSO supplied an explicit
			// client_id query param, it must appear in the
			// hint's aud list. Otherwise we'd accept a hint for
			// "cli-A" while the caller claims to be "cli-B" —
			// a misconfiguration that should fail loudly.
			if clientID != "" && !containsString(hint.Audience, clientID) {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "id_token_hint audience does not match client_id",
				})
				return
			}
		}

		// This browser's session, resolved once. Resolve returns an error ONLY
		// for store / infrastructure failures — an unknown or dead cookie is
		// (nil, nil) and is not an incident.
		cookieVal, hasCookie := deps.CookieSession.Read(c.Request)
		var resolved *service.CookieSessionLookupResult
		var resolveErr error
		if hasCookie {
			resolved, resolveErr = deps.CookieSession.Resolve(c.Request.Context(), cookieVal)
		}

		// A GET can be fired from any page: ask before ending this browser's
		// session unless a verified hint shows the request came from an app
		// this person signed in to, in this session (RP-Initiated Logout 1.0
		// §2: the OP MUST ask when there is no hint or the ID token does not
		// belong to the current session or End-User). The page's link carries
		// a value only the browser holding the cookie was shown.
		if hasCookie && !logoutConfirmed(c, cookieVal) && !hintVouchesForBrowser(hint, resolved, resolveErr) {
			renderSignOutConfirmPage(c, cookieVal)
			return
		}

		// endedFor names the user of each session this request ends, so each
		// relying party's logout token names that session's own user.
		endedFor := map[uuid.UUID]uuid.UUID{}

		// Phase 1: revoke the cookie session (best-effort — but never
		// silently: THE-LOGOUT-THAT-CANNOT-REVOKE. A STORE error while
		// resolving or revoking is logged with the correlation id, audited
		// as user_session.logout.revocation_unconfirmed and marked on the
		// response; the cookie is still cleared below because the user
		// asked to leave this device.)
		var cookieResolvedSessionID uuid.UUID
		var cookieResolvedUserID uuid.UUID
		revocationUnconfirmed := false
		if hasCookie {
			switch {
			case resolveErr != nil:
				noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "cookie-session", resolveErr)
				revocationUnconfirmed = true
			case resolved != nil && resolved.Session != nil:
				cookieResolvedSessionID = resolved.Session.ID
				if resolved.User != nil {
					cookieResolvedUserID = resolved.User.ID
				}
				endedFor[cookieResolvedSessionID] = cookieResolvedUserID
				if rerr := deps.UserSession.RevokeSession(c.Request.Context(), resolved.Session.ID, "oidc_logout"); rerr != nil {
					noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "revoke-session", rerr)
					revocationUnconfirmed = true
				} else {
					if deps.BrowserTokens != nil {
						if berr := deps.BrowserTokens.Revoke(c.Request.Context(), cookieVal); berr != nil {
							noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "browser-token", berr)
							revocationUnconfirmed = true
						}
					}
					_ = deps.Audit.Record(c.Request.Context(), audit.Event{
						Action:    "user_session.logout.cookie_revoked",
						Outcome:   "success",
						IPAddress: c.ClientIP(),
						UserAgent: c.Request.UserAgent(),
						Metadata: map[string]any{
							"session_id": resolved.Session.ID.String(),
						},
					})
				}
			}
		}
		// Phase 2: revoke the session referenced by the hint
		// (when present and the hint carried a sid claim).
		// This covers the "bearer-driven logout" pattern where
		// the RP forwards an ID token instead of a cookie.
		if hint != nil && hint.SessionID != (domain.Principal{}).SessionID {
			if _, seen := endedFor[hint.SessionID]; !seen {
				endedFor[hint.SessionID] = hint.Subject
			}
			if rerr := deps.UserSession.RevokeSession(c.Request.Context(), hint.SessionID, "oidc_logout"); rerr != nil {
				noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "hint-session", rerr)
				revocationUnconfirmed = true
			}
		}
		// Phase 3: revoke a bearer-presented session (if any).
		var bearerSessionID uuid.UUID
		if principal, ok := mw.PrincipalFromContext(c); ok && principal != nil && principal.SessionID != (domain.Principal{}).SessionID {
			bearerSessionID = principal.SessionID
			if _, seen := endedFor[bearerSessionID]; !seen {
				endedFor[bearerSessionID] = principal.UserID
			}
			if rerr := deps.UserSession.RevokeSession(c.Request.Context(), principal.SessionID, "oidc_logout"); rerr != nil {
				noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "bearer-session", rerr)
				revocationUnconfirmed = true
			}
		}

		// Phase 3b: tell the relying parties (OIDC Back-Channel Logout 1.0 §2).
		// Every relying party recorded for an ended session that registered a
		// back-channel endpoint gets a logout token, not only the one that
		// asked. A delivery that fails never stops the others or the logout.
		notified := map[string]struct{}{}
		// The subject of a logout token is the user of the session it ends;
		// with no session to name, the cookie's user or the hint's subject.
		logoutSubject := cookieResolvedUserID
		if logoutSubject == uuid.Nil && hint != nil {
			logoutSubject = hint.Subject
		}
		subjectOf := func(sid uuid.UUID) uuid.UUID {
			if sub, ok := endedFor[sid]; ok && sub != uuid.Nil {
				return sub
			}
			return logoutSubject
		}
		if deps.BackchannelDelivery != nil && deps.SessionRPs != nil && deps.Clients != nil {
			ended := []uuid.UUID{cookieResolvedSessionID, bearerSessionID}
			if hint != nil {
				ended = append(ended, hint.SessionID)
			}
			for _, sid := range ended {
				if sid == uuid.Nil {
					continue
				}
				clientIDs, rpErr := deps.SessionRPs.ClientIDs(c.Request.Context(), sid)
				if rpErr != nil {
					noteLogoutRevocationUnconfirmed(c, deps.Audit, "end_session", "session-relying-parties", rpErr)
					continue
				}
				for _, cid := range clientIDs {
					key := cid + "|" + sid.String()
					if _, done := notified[key]; done {
						continue
					}
					rp, lerr := deps.Clients.GetClientByClientID(c.Request.Context(), cid)
					if lerr != nil || rp == nil || rp.BackchannelLogoutURI == "" {
						continue
					}
					notified[key] = struct{}{}
					deliverBackchannelLogout(c, deps, rp, subjectOf(sid), sid)
				}
			}
		}

		// Phase 4: clear cookie.
		writeSessionCookie(c, deps.CookieSession.Clear())

		// Phase 5: maybe redirect. D-018a: with no post_logout_redirect_uri
		// the browser lands on the IdP's own signed-out page (it used to get
		// a bare 204 and an aborted navigation).
		if postLogoutRedirectURI == "" {
			renderSignedOutPage(c)
			return
		}
		// Resolve the client used to validate the redirect URI.
		// Order:
		//   1. explicit client_id query param wins.
		//   2. otherwise: first aud entry on the verified hint
		//      that resolves to a registered client.
		resolvedClient, ok, clientStoreErr := resolveLogoutClient(c.Request.Context(), deps, clientID, hint)
		if clientStoreErr != nil {
			// THE-LOGOUT-THAT-CANNOT-REVOKE: the client STORE did not answer, so
			// post_logout_redirect_uri cannot be validated and the RP redirect
			// must not happen (an unvalidated redirect is an open redirect).
			// The cookie is already cleared above; the browser gets the honest
			// 503 with the correlation id instead of a silent 204.
			respondAuthStoreUnavailable(c, "logout.client", clientStoreErr)
			return
		}
		if !ok {
			c.Status(http.StatusNoContent)
			return
		}
		if !isPostLogoutRedirectURIAllowed(resolvedClient, postLogoutRedirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		// Back-channel logout delivery (when the resolved client
		// has a backchannel_logout_uri AND we have something to
		// stamp into the token's sub/sid claims). Errors are
		// non-fatal — the logout still completes for the user.
		if deps.BackchannelDelivery != nil && resolvedClient.BackchannelLogoutURI != "" {
			sid := cookieResolvedSessionID
			if sid == uuid.Nil && hint != nil {
				sid = hint.SessionID
			}
			// The fan-out above already reached it when it was recorded for the
			// session; only a client it did not reach is delivered to here.
			if _, done := notified[resolvedClient.ClientID+"|"+sid.String()]; !done {
				deliverBackchannelLogout(c, deps, resolvedClient, subjectOf(sid), sid)
			}
		}
		location := postLogoutRedirectURI
		if state != "" {
			location = appendQueryParam(location, "state", state)
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.logout.redirected",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":              resolvedClient.ClientID,
				"hint_used":              hint != nil,
				"explicit_client":        clientID != "",
				"revocation_unconfirmed": revocationUnconfirmed,
			},
		})
		// The RP flow completes either way: state rides on the redirect.
		// An unconfirmed revocation is already marked on this response
		// (X-Identuum-Logout) and in the audit trail.
		c.Redirect(http.StatusFound, location)
	}
}

// deliverBackchannelLogout posts one relying party's logout token, after the
// response when the handler was given a background runner, and audits the
// outcome. Its failure is never the user's: the logout has already happened.
func deliverBackchannelLogout(c *gin.Context, deps EndSessionHandlerDeps, rp *domain.Client, subject, sessionID uuid.UUID) {
	ip, ua := c.ClientIP(), c.Request.UserAgent()
	deliver := func(ctx context.Context) {
		result, derr := deps.BackchannelDelivery.Deliver(ctx, service.DeliverInput{
			Client:    rp,
			Subject:   subject,
			SessionID: sessionID,
		})
		deliveryStatus := "success"
		if derr != nil {
			deliveryStatus = "failed"
		}
		meta := map[string]any{
			"client_id": rp.ClientID,
			"status":    deliveryStatus,
		}
		if result != nil {
			meta["http_status"] = result.Status
		}
		_ = deps.Audit.Record(ctx, audit.Event{
			Action:    "user_session.backchannel_logout.delivered",
			Outcome:   deliveryStatus,
			IPAddress: ip,
			UserAgent: ua,
			Metadata:  meta,
		})
	}
	if deps.Background == nil {
		deliver(c.Request.Context())
		return
	}
	deps.Background(c.Request.Context(), deliver)
}

// signedOutPage is the IdP's own landing after RP-initiated logout with no
// post_logout_redirect_uri (owner ruling D-018a). Static: it names no user,
// client or state, runs no script and loads nothing.
const signedOutPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Signed out — Identuum</title>
  <style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1c1917}h1{font-size:1.5rem}</style>
</head>
<body>
  <main>
    <h1>You are signed out</h1>
    <p>Your session with the identity provider has ended. You can close this window.</p>
  </main>
</body>
</html>`

// renderSignedOutPage writes signedOutPage: 200, never cached, and a CSP that
// forbids scripts, framing, forms and every other load (the one inline style
// is allowed by its hash-free 'unsafe-inline' style directive only).
func renderSignedOutPage(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.String(http.StatusOK, signedOutPage)
}

// hintVouchesForBrowser reports whether a verified id_token_hint shows the
// sign-out request came from an app the person signed in on this browser
// signed in to, in this session: the hint's subject is the cookie session's
// user and, when the hint names a session (sid), it is this one. With no live
// session on the browser there is nothing of the browser's to protect. A store
// error resolving the cookie vouches for nothing: the person is asked.
func hintVouchesForBrowser(hint *service.VerifiedIDTokenHint, resolved *service.CookieSessionLookupResult, resolveErr error) bool {
	if hint == nil || resolveErr != nil {
		return false
	}
	if resolved == nil || resolved.Session == nil {
		return true
	}
	if resolved.User == nil || hint.Subject == uuid.Nil || resolved.User.ID != hint.Subject {
		return false
	}
	return hint.SessionID == uuid.Nil || hint.SessionID == resolved.Session.ID
}

// logoutConfirmToken is the value the confirmation page's link carries. It is
// keyed by the session cookie's own value, so only a browser that holds the
// cookie was ever shown it: a page that fires the end-session request from
// elsewhere cannot compute it.
func logoutConfirmToken(sessionCookieValue string) string {
	mac := hmac.New(sha256.New, []byte(sessionCookieValue))
	mac.Write([]byte("identuum end-session confirmation"))
	return hex.EncodeToString(mac.Sum(nil))
}

// logoutConfirmed reports whether the request carries the confirm value for the
// session cookie it came with.
func logoutConfirmed(c *gin.Context, sessionCookieValue string) bool {
	return hmac.Equal([]byte(c.Query("confirm")), []byte(logoutConfirmToken(sessionCookieValue)))
}

const signOutConfirmPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign out — Identuum</title>
  <style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1c1917}h1{font-size:1.5rem}a{display:inline-block;padding:.5rem 1rem;border:1px solid #1c1917;border-radius:.375rem;color:#1c1917;text-decoration:none}</style>
</head>
<body>
  <main>
    <h1>Sign out?</h1>
    <p>An application asked to end your session with the identity provider.</p>
    <p><a href="%s">Sign out</a></p>
  </main>
</body>
</html>`

// renderSignOutConfirmPage asks the person before the session is ended: 200,
// never cached, no scripts, no framing. Its one link is the same request with
// the confirm value for this browser's session cookie added.
func renderSignOutConfirmPage(c *gin.Context, sessionCookieValue string) {
	q := c.Request.URL.Query()
	q.Set("confirm", logoutConfirmToken(sessionCookieValue))
	link := c.Request.URL.Path + "?" + q.Encode()
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	c.String(http.StatusOK, fmt.Sprintf(signOutConfirmPage, html.EscapeString(link)))
}

// resolveLogoutClient returns the *domain.Client whose
// PostLogoutRedirectURIs allowlist gates the redirect. Returns
// (nil, false, nil) when no client can be safely resolved (unknown client —
// a verdict), and (nil, false, err) when the client STORE did not answer
// (THE-LOGOUT-THAT-CANNOT-REVOKE: the caller answers 503, never a silent
// 204 and never an unvalidated redirect).
func resolveLogoutClient(
	ctx context.Context,
	deps EndSessionHandlerDeps,
	explicitClientID string,
	hint *service.VerifiedIDTokenHint,
) (*domain.Client, bool, error) {
	if deps.Clients == nil {
		return nil, false, nil
	}
	if strings.TrimSpace(explicitClientID) != "" {
		client, err := deps.Clients.GetClientByClientID(ctx, explicitClientID)
		if err != nil && !errors.Is(err, domain.ErrClientNotFound) {
			return nil, false, domain.AuthStoreUnavailable("client", err)
		}
		if err != nil || client == nil {
			return nil, false, nil
		}
		return client, true, nil
	}
	if hint != nil {
		for _, aud := range hint.Audience {
			if aud == "" {
				continue
			}
			client, err := deps.Clients.GetClientByClientID(ctx, aud)
			if err != nil && !errors.Is(err, domain.ErrClientNotFound) {
				return nil, false, domain.AuthStoreUnavailable("client", err)
			}
			if err == nil && client != nil {
				return client, true, nil
			}
		}
	}
	return nil, false, nil
}

// containsString is a tiny helper used for hint-aud matching.
func containsString(xs []string, want string) bool {
	return slices.Contains(xs, want)
}

// isPostLogoutRedirectURIAllowed reports whether the supplied URI
// is in the client's PostLogoutRedirectURIs allowlist.
func isPostLogoutRedirectURIAllowed(c *domain.Client, candidate string) bool {
	if c == nil {
		return false
	}
	return slices.Contains(c.PostLogoutRedirectURIs, candidate)
}

// appendQueryParam appends ?k=v or &k=v to the URL string. Returns
// the original URL on parse failure.
func appendQueryParam(raw, k, v string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String()
}
