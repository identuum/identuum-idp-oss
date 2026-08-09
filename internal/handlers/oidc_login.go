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
