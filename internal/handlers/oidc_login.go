package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// upstreamLoginCookie binds an upstream sign-in to the browser that started it:
// initiation plants it holding the state, the callback requires it. Each
// sign-in has its own cookie, named from its state (upstreamLoginCookieName),
// so a second sign-in started in the same browser does not void the first.
const upstreamLoginCookie = "idp_login_state"

// upstreamLoginCookieName is the binding cookie's name for one state: the
// prefix and the first 16 hex characters of the state's SHA-256.
func upstreamLoginCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return upstreamLoginCookie + "_" + hex.EncodeToString(sum[:8])
}

// upstreamLoginCookieTTL bounds the binding cookie's life, in seconds. The
// state it holds expires server-side on its own; this only keeps a stale
// cookie from lingering.
const upstreamLoginCookieTTL = 10 * 60

// upstreamLoginState reads the state out of the authorize URL the service built.
func upstreamLoginState(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

// setUpstreamLoginBinding plants the host-only cookie that ties the sign-in to
// this browser. It is sent on the top-level navigation back from the provider
// (SameSite=Lax). Its path is "/" so a proxy that prefixes the callback path
// does not hide it.
func setUpstreamLoginBinding(c *gin.Context, state string) {
	writeSessionCookie(c, &http.Cookie{
		Name: upstreamLoginCookieName(state), Value: state, Path: "/",
		MaxAge: upstreamLoginCookieTTL, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// clearUpstreamLoginBinding expires this sign-in's binding cookie once it is
// done.
func clearUpstreamLoginBinding(c *gin.Context, state string) {
	writeSessionCookie(c, &http.Cookie{
		Name: upstreamLoginCookieName(state), Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// upstreamLoginBound reports whether the request carries the cookie planted at
// initiation for exactly this state.
func upstreamLoginBound(c *gin.Context, state string) bool {
	held, err := c.Cookie(upstreamLoginCookieName(state))
	return err == nil && subtle.ConstantTimeCompare([]byte(held), []byte(state)) == 1
}

// OIDCLoginInitiator is the narrow initiation seam the handler consumes.
// *service.OIDCLoginService satisfies it.
type OIDCLoginInitiator interface {
	InitiateLogin(ctx context.Context, providerID uuid.UUID, returnURL string) (string, error)
}

// OIDCLoginHandlerDeps wires the always-public upstream-OIDC login-initiation
// endpoint (OSS basic single-provider login — Slice 4 of
// docs/design/oss-basic-oidc-login.md).
//
// OIDCLogin is REQUIRED — when nil the route is simply absent (optional
// feature, no fault). The endpoint takes no bearer/cookie to start: it
// redirects the browser to the upstream provider's authorize URL.
type OIDCLoginHandlerDeps struct {
	OIDCLogin OIDCLoginInitiator
	Audit     audit.Service
}

// RegisterOIDCLoginRoutes mounts
//
//	GET /api/v1/auth/idp/:id/login   (public)
//
// onto router. Nil OIDCLogin ⇒ the route is not mounted (the surface is
// optional until the org configures a provider + the runtime wires it).
func RegisterOIDCLoginRoutes(router gin.IRouter, deps OIDCLoginHandlerDeps) {
	if deps.OIDCLogin == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// docgen:endpoint
	// docgen:surface=oidc-login
	// docgen:method=GET
	// docgen:path=/api/v1/auth/idp/:id/login
	// docgen:summary=Begin upstream single-provider OIDC login: resolve the org's configured OIDC provider by id, fetch its discovery metadata, mint state/nonce/PKCE, persist the OIDCState, and 302-redirect to the provider's authorize URL.
	// docgen:tier=oss
	// docgen:auth=public
	// docgen:notes=Anonymous (no bearer/cookie to start). {id} is an identity_providers row id; it must be type=oidc and active or the response is 404. An optional ?return_to= is a same-site relative path only (open-redirect defense; off-site is replaced with "/"). The PKCE verifier is persisted encrypted, never returned or logged. Upstream discovery is https-only + SSRF-guarded; a discovery failure returns 502 with no redirect. This is initiation only — the callback (token exchange + ID-token validation + JIT + session) is a later slice.
	router.GET("/api/v1/auth/idp/:id/login", HandleOIDCLoginInitiation(deps))
}

// HandleOIDCLoginInitiation resolves the provider, mints + persists the
// OIDCState via the login service, and 302-redirects to the upstream
// authorize URL. Every failure is a clean status with nothing leaked.
func HandleOIDCLoginInitiation(deps OIDCLoginHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		providerID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
			return
		}
		authURL, err := deps.OIDCLogin.InitiateLogin(c.Request.Context(), providerID, c.Query("return_to"))
		if err != nil {
			switch {
			case errors.Is(err, service.ErrLoginProviderNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
			case errors.Is(err, service.ErrLoginDiscoveryFailed):
				c.JSON(http.StatusBadGateway, gin.H{"error": "upstream provider discovery failed"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}
		// Bind the sign-in to this browser; an authorize URL with no state
		// cannot be bound, so it is not followed.
		state := upstreamLoginState(authURL)
		if state == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		setUpstreamLoginBinding(c, state)
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "auth.oidc_login_initiated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"provider_id": providerID.String()},
		})
		c.Redirect(http.StatusFound, authURL)
	}
}
