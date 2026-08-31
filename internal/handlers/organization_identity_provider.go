package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mappers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/types"
)

// OrganizationIdentityProviderHandlerDeps wires the org-admin surface that
// configures an organization's SINGLE upstream OIDC provider (OSS basic
// single-provider login — Slice 2 of docs/design/oss-basic-oidc-login.md).
//
// Authority: org_admin, OWN-ORG ONLY. site_admin does NOT manage tenant
// identity providers (per the admin authority model) — it is refused with
// 403 by the handler even though it satisfies the shared org-scope guard.
// Cross-org org_admin probes are rejected 403 by
// RequireSiteAdminOrSameOrgAdminWithScopesAudit BEFORE the handler runs.
//
// This surface manages the ONE oidc provider per org — never a list, never
// routing/HRD (that is the CE multi-IdP surface). client_secret is
// write-only: accepted in the request Config, never returned by any
// response (the types.ProviderConfig DTO + ToIdentityProviderInfo carry no
// secret field).
type OrganizationIdentityProviderHandlerDeps struct {
	OIDCProviderConfigService *service.OIDCProviderConfigService
	Audit                     audit.Service
	StartupReport             *lifecycle.StartupReport
}

// RegisterOrganizationIdentityProviderRoutes mounts the org-admin config
// API for the org's single OIDC provider.
//
// Routes (org_admin own-org only; site_admin refused):
//
//	POST   /api/v1/organizations/:id/identity-provider   (idps:create)
//	GET    /api/v1/organizations/:id/identity-provider   (idps:read)
//	PUT    /api/v1/organizations/:id/identity-provider   (idps:update)
//	DELETE /api/v1/organizations/:id/identity-provider   (idps:delete)
func RegisterOrganizationIdentityProviderRoutes(router gin.IRouter, deps OrganizationIdentityProviderHandlerDeps) {
	if deps.OIDCProviderConfigService == nil {
		// P-018: the org IdP config surface governs upstream login for a
		// tenant — security-relevant. Record the fault and mount a uniform
		// service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"organization-identity-provider-routes",
			"org identity-provider config surface unavailable: OIDCProviderConfigService not wired",
		)
		g := router.Group("/api/v1/organizations/:id/identity-provider")
		g.POST("", serviceMissingFallback("organization-identity-provider"))
		g.GET("", serviceMissingFallback("organization-identity-provider"))
		g.PUT("", serviceMissingFallback("organization-identity-provider"))
		g.DELETE("", serviceMissingFallback("organization-identity-provider"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/organizations/:id/identity-provider")

	createGroup := g.Group("")
	createGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeIDPsCreate))

	// docgen:endpoint
	// docgen:surface=organization-identity-provider
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/identity-provider
	// docgen:summary=Create the organization's single upstream OIDC identity provider (OSS basic single-provider login). Rejects a second provider (one per org) and any non-oidc type (ldap/ad are CE).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.IdentityProviderResponse
	// docgen:notes=org_admin OWN-ORG only with the idps:create scope; site_admin is refused 403 (site_admin does not manage tenant IdPs); cross-org 403 via the shared scope middleware. client_secret is accepted in the request config but is WRITE-ONLY — no response ever returns it (stored encrypted at rest via the CryptoService). Emits org.identity_provider_created audit with target_organization_id + provider_id + type; never secrets.
	// docgen:status=201
	createGroup.POST("", HandleCreateOrganizationIdentityProvider(deps))

	readGroup := g.Group("")
	readGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeIDPsRead))

	// docgen:endpoint
	// docgen:surface=organization-identity-provider
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/identity-provider
	// docgen:summary=Read the organization's single OIDC identity provider configuration. client_secret is never included.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.IdentityProviderResponse
	// docgen:notes=org_admin OWN-ORG only with the idps:read scope; site_admin refused 403; cross-org 403. Returns 404 when the org has no oidc provider. The response omits client_secret entirely (write-only).
	readGroup.GET("", HandleGetOrganizationIdentityProvider(deps))

	updateGroup := g.Group("")
	updateGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeIDPsUpdate))

	// docgen:endpoint
	// docgen:surface=organization-identity-provider
	// docgen:method=PUT
	// docgen:path=/api/v1/organizations/:id/identity-provider
	// docgen:summary=Update the organization's single OIDC identity provider. The client_secret is re-encrypted only if a new one is supplied; omitting it preserves the stored secret.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.IdentityProviderResponse
	// docgen:notes=org_admin OWN-ORG only with the idps:update scope; site_admin refused 403; cross-org 403. Type stays oidc. An empty client_secret preserves the stored ciphertext; a supplied one re-encrypts. Response omits client_secret. Emits org.identity_provider_updated audit; never secrets.
	updateGroup.PUT("", HandleUpdateOrganizationIdentityProvider(deps))

	deleteGroup := g.Group("")
	deleteGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeIDPsDelete))

	// docgen:endpoint
	// docgen:surface=organization-identity-provider
	// docgen:method=DELETE
	// docgen:path=/api/v1/organizations/:id/identity-provider
	// docgen:summary=Delete the organization's single OIDC identity provider.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.identityProviderDeleteResponse
	// docgen:notes=org_admin OWN-ORG only with the idps:delete scope; site_admin refused 403; cross-org 403. Returns 404 when the org has no oidc provider. Emits org.identity_provider_deleted audit; never secrets.
	deleteGroup.DELETE("", HandleDeleteOrganizationIdentityProvider(deps))
}

// denySiteAdminTenantIDP refuses a site_admin principal with 403. site_admin
// is infrastructure authority, not a tenant super-admin — it does not manage
// tenant-owned identity providers. The shared org-scope guard lets site_admin
// through (c.Next), so this handler-level gate enforces the tenant-ownership
// rule. Returns true when the request was refused (response already written).
func denySiteAdminTenantIDP(c *gin.Context) bool {
	p, ok := mw.PrincipalFromContext(c)
	if ok && p != nil && p.IsSiteAdmin() {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "site_admin does not manage tenant identity providers; delegate to an org_admin",
		})
		return true
	}
	return false
}

// identityProviderDeleteResponse is the delete acknowledgement shape.
type identityProviderDeleteResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// HandleCreateOrganizationIdentityProvider creates the org's single OIDC
// provider. The client_secret arrives in the request config and is encrypted
// by the service; the response projection omits it.
func HandleCreateOrganizationIdentityProvider(deps OrganizationIdentityProviderHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if denySiteAdminTenantIDP(c) {
			return
		}
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		var req types.CreateIdentityProviderRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// CreateIdentityProviderRequest.Slug carries binding:"required", so
		// the wire has already refused an absent or empty slug here; passing
		// a pointer keeps the service contract identical on both paths.
		in := oidcInputFromConfig(orgID, req.Type, req.Name, &req.Slug, req.Config)
		provider, err := deps.OIDCProviderConfigService.CreateOIDCProvider(c.Request.Context(), in)
		if err != nil {
			respondOIDCConfigError(c, err)
			return
		}
		c.JSON(http.StatusCreated, types.IdentityProviderResponse{
			Success:          true,
			Message:          "identity provider created",
			IdentityProvider: mappers.ToIdentityProviderInfo(provider),
		})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org.identity_provider_created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"target_organization_id": orgID.String(),
				"provider_id":            provider.ID.String(),
				"type":                   string(provider.Type),
			},
		})
	}
}

// HandleGetOrganizationIdentityProvider returns the org's single OIDC
// provider, or 404 when none is configured. Never returns client_secret.
func HandleGetOrganizationIdentityProvider(deps OrganizationIdentityProviderHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if denySiteAdminTenantIDP(c) {
			return
		}
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		provider, err := deps.OIDCProviderConfigService.GetOIDCProvider(c.Request.Context(), orgID)
		if err != nil {
			respondOIDCConfigError(c, err)
			return
		}
		c.JSON(http.StatusOK, types.IdentityProviderResponse{
			Success:          true,
			IdentityProvider: mappers.ToIdentityProviderInfo(provider),
		})
	}
}

// HandleUpdateOrganizationIdentityProvider updates the org's single OIDC
// provider. Omitting client_secret preserves the stored ciphertext.
func HandleUpdateOrganizationIdentityProvider(deps OrganizationIdentityProviderHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if denySiteAdminTenantIDP(c) {
			return
		}
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		var req types.UpdateIdentityProviderRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// Update always targets the org's single oidc provider; the update
		// DTO carries no type, so oidc is fixed here (the service re-checks).
		in := oidcInputFromConfig(orgID, domain.IDPTypeOIDC, req.Name, req.Slug, req.Config)
		provider, err := deps.OIDCProviderConfigService.UpdateOIDCProvider(c.Request.Context(), orgID, in)
		if err != nil {
			respondOIDCConfigError(c, err)
			return
		}
		c.JSON(http.StatusOK, types.IdentityProviderResponse{
			Success:          true,
			Message:          "identity provider updated",
			IdentityProvider: mappers.ToIdentityProviderInfo(provider),
		})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org.identity_provider_updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"target_organization_id": orgID.String(),
				"provider_id":            provider.ID.String(),
				"type":                   string(provider.Type),
			},
		})
	}
}

// HandleDeleteOrganizationIdentityProvider removes the org's single OIDC
// provider. Resolves it first so a missing provider returns 404.
func HandleDeleteOrganizationIdentityProvider(deps OrganizationIdentityProviderHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if denySiteAdminTenantIDP(c) {
			return
		}
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		provider, err := deps.OIDCProviderConfigService.GetOIDCProvider(c.Request.Context(), orgID)
		if err != nil {
			respondOIDCConfigError(c, err)
			return
		}
		if err := deps.OIDCProviderConfigService.DeleteOIDCProvider(c.Request.Context(), orgID, provider.ID); err != nil {
			respondOIDCConfigError(c, err)
			return
		}
		c.JSON(http.StatusOK, identityProviderDeleteResponse{Success: true, Message: "identity provider deleted"})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org.identity_provider_deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"target_organization_id": orgID.String(),
				"provider_id":            provider.ID.String(),
			},
		})
	}
}

// oidcInputFromConfig maps the request's generic config map to the typed
// service input. Structured fields come from the typed types.ProviderConfig
// (which has NO secret field); the write-only client_secret is read
// separately from the raw map so it never round-trips through a response DTO.
func oidcInputFromConfig(orgID uuid.UUID, typ domain.IdentityProviderType, name string, slug *string, cfg map[string]any) service.OIDCProviderInput {
	var dto types.ProviderConfig
	if len(cfg) > 0 {
		if raw, err := json.Marshal(cfg); err == nil {
			_ = json.Unmarshal(raw, &dto)
		}
	}
	clientSecret, _ := cfg["client_secret"].(string)
	return service.OIDCProviderInput{
		OrganizationID:       orgID,
		Type:                 typ,
		Name:                 name,
		Slug:                 slug,
		IssuerURL:            dto.IssuerURL,
		ClientID:             dto.ClientID,
		ClientSecret:         clientSecret,
		Scopes:               dto.Scopes,
		RedirectURIs:         dto.RedirectURIs,
		EmailDomains:         dto.EmailDomains,
		ClaimMapping:         dto.ClaimMapping,
		AttributeMapping:     dto.AttributeMapping,
		PKCERequired:         dto.PKCERequired,
		AllowExternalDomains: dto.AllowExternalDomains,
	}
}

// respondOIDCConfigError maps the config service's sentinels to HTTP codes,
// reusing the project's flat {"error": ...} envelope. No secret is ever
// echoed in an error.
func respondOIDCConfigError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrOIDCProviderExists()):
		c.JSON(http.StatusConflict, gin.H{"error": "an OIDC provider already exists for this organization"})
	case errors.Is(err, service.ErrUnsupportedProviderType()):
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported identity provider type: OSS supports oidc only"})
	case errors.Is(err, service.ErrInvalidIssuerURL()):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid issuer/discovery URL: must be a well-formed https URL"})
	case errors.Is(err, service.ErrOIDCProviderInvalidInput()):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OIDC provider configuration"})
	case errors.Is(err, service.ErrOIDCProviderNotFound()):
		c.JSON(http.StatusNotFound, gin.H{"error": "no OIDC provider configured for this organization"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
