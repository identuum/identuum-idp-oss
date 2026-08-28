package handlers

import (
	"context"
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
	CookieSession       *service.CookieSessionService
	UserSession         *service.UserSessionService
	Clients             ConsentClientLookup
	IDTokenVerifier     *service.IDTokenVerifier
	BackchannelDelivery *service.BackchannelLogoutService
	BrowserTokens       *service.BrowserSessionTokenService
	Audit               audit.Service
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
	// docgen:notes=Anonymous callers receive the same end-session UX (idempotent) — no session is required for the route to terminate cleanly. Terminal success is 204 (no post_logout_redirect_uri) OR a 302 redirect to the validated post_logout_redirect_uri; with two success codes there is no single status to pin, so it is intentionally left unannotated and defaults to 200 in the spec (never guessed from the method).
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
// `id_token_hint` is currently parsed only to extract `client_id`
// from the `aud` claim — full signature verification is deferred to
// a future slice (the bearer-token verifier path already does
// signature verification when a bearer is presented). Operators
// requiring id_token_hint verification MUST front the IDP with a
// reverse proxy that strips unsigned hints, or wait for the
// follow-up slice.
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
			verified, err := deps.IDTokenVerifier.Verify(c.Request.Context(), idTokenHint)
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

		// Phase 1: revoke the cookie session (best-effort).
		var cookieResolvedSessionID uuid.UUID
		var cookieResolvedUserID uuid.UUID
		if cookieVal, ok := deps.CookieSession.Read(c.Request); ok {
			if resolved, err := deps.CookieSession.Resolve(c.Request.Context(), cookieVal); err == nil && resolved != nil && resolved.Session != nil {
				cookieResolvedSessionID = resolved.Session.ID
				if resolved.User != nil {
					cookieResolvedUserID = resolved.User.ID
				}
				_ = deps.UserSession.RevokeSession(c.Request.Context(), resolved.Session.ID, "oidc_logout")
				if deps.BrowserTokens != nil {
					_ = deps.BrowserTokens.Revoke(c.Request.Context(), cookieVal)
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
		// Phase 2: revoke the session referenced by the hint
		// (when present and the hint carried a session_id claim).
		// This covers the "bearer-driven logout" pattern where
		// the RP forwards an ID token instead of a cookie.
		if hint != nil && hint.SessionID != (domain.Principal{}).SessionID {
			_ = deps.UserSession.RevokeSession(c.Request.Context(), hint.SessionID, "oidc_logout")
		}
		// Phase 3: revoke a bearer-presented session (if any).
		if principal, ok := mw.PrincipalFromContext(c); ok && principal != nil && principal.SessionID != (domain.Principal{}).SessionID {
			_ = deps.UserSession.RevokeSession(c.Request.Context(), principal.SessionID, "oidc_logout")
		}

		// Phase 4: clear cookie.
		writeSessionCookie(c, deps.CookieSession.Clear())

		// Phase 5: maybe redirect.
		if postLogoutRedirectURI == "" {
			c.Status(http.StatusNoContent)
			return
		}
		// Resolve the client used to validate the redirect URI.
		// Order:
		//   1. explicit client_id query param wins.
		//   2. otherwise: first aud entry on the verified hint
		//      that resolves to a registered client.
		resolvedClient, ok := resolveLogoutClient(c.Request.Context(), deps, clientID, hint)
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
			subject := cookieResolvedUserID
			if subject == uuid.Nil && hint != nil {
				subject = hint.Subject
			}
			sid := cookieResolvedSessionID
			if sid == uuid.Nil && hint != nil {
				sid = hint.SessionID
			}
			result, derr := deps.BackchannelDelivery.Deliver(c.Request.Context(), service.DeliverInput{
				Client:    resolvedClient,
				Subject:   subject,
				SessionID: sid,
			})
			deliveryStatus := "success"
			if derr != nil {
				deliveryStatus = "failed"
			}
			meta := map[string]any{
				"client_id": resolvedClient.ClientID,
				"status":    deliveryStatus,
			}
			if result != nil {
				meta["http_status"] = result.Status
			}
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user_session.backchannel_logout.delivered",
				Outcome:   deliveryStatus,
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				Metadata:  meta,
			})
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
				"client_id":       resolvedClient.ClientID,
				"hint_used":       hint != nil,
				"explicit_client": clientID != "",
			},
		})
		c.Redirect(http.StatusFound, location)
	}
}

// resolveLogoutClient returns the *domain.Client whose
// PostLogoutRedirectURIs allowlist gates the redirect. Returns
// (nil, false) when no client can be safely resolved.
func resolveLogoutClient(
	ctx context.Context,
	deps EndSessionHandlerDeps,
	explicitClientID string,
	hint *service.VerifiedIDTokenHint,
) (*domain.Client, bool) {
	if deps.Clients == nil {
		return nil, false
	}
	if strings.TrimSpace(explicitClientID) != "" {
		client, err := deps.Clients.GetClientByClientID(ctx, explicitClientID)
		if err != nil || client == nil {
			return nil, false
		}
		return client, true
	}
	if hint != nil {
		for _, aud := range hint.Audience {
			if aud == "" {
				continue
			}
			client, err := deps.Clients.GetClientByClientID(ctx, aud)
			if err == nil && client != nil {
				return client, true
			}
		}
	}
	return nil, false
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
