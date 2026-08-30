package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OrganizationDomainsHandlerDeps wires the per-org domains routes.
//
// OrganizationDomainService is required (read-only repository
// fallback is not exposed at this slice — the sensitive token
// state in the table is only safe to expose through a service that
// strips it before projection).
type OrganizationDomainsHandlerDeps struct {
	OrganizationDomainService *service.OrganizationDomainService
	Audit                     audit.Service

	// StartupReport receives a fatal fault if the service is not wired —
	// instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterOrganizationDomainsRoutes mounts the org-domains routes
// onto router. They follow the monolith's path shape:
//
//	GET    /api/v1/organizations/:id/domains                       (site_admin OR same-org org_admin)
//	POST   /api/v1/organizations/:id/domains                       (site_admin OR same-org org_admin)
//	POST   /api/v1/organizations/:id/domains/:domain_id/verify     (site_admin OR same-org org_admin)
//	DELETE /api/v1/organizations/:id/domains/:domain_id            (site_admin OR same-org org_admin)
//	POST   /api/v1/organizations/:id/domains/:domain_id/primary    (site_admin OR same-org org_admin)
//
// Authority decision: per Identuum's admin authority model,
// org_admin manages only their own organization. The path :id is
// the target organization, so RequireSiteAdminOrSameOrgAdmin binds
// the route's target tenant to the principal's home tenant for
// org_admin actors and lets site_admin act across tenants.
func RegisterOrganizationDomainsRoutes(router gin.IRouter, deps OrganizationDomainsHandlerDeps) {
	if deps.OrganizationDomainService == nil {
		// P-018: org-domain verification is identity/tenant-binding
		// critical. FATAL. Record the fault + mount a service-missing
		// fallback instead of panicking.
		deps.StartupReport.Fatal(
			"organization-domains-routes",
			"organization-domains admin surface unavailable: OrganizationDomainService not wired",
		)
		g := router.Group("/api/v1/organizations/:id/domains")
		g.GET("", serviceMissingFallback("organization-domains"))
		g.POST("", serviceMissingFallback("organization-domains"))
		g.POST("/:domain_id/verify", serviceMissingFallback("organization-domains"))
		g.DELETE("/:domain_id", serviceMissingFallback("organization-domains"))
		g.POST("/:domain_id/primary", serviceMissingFallback("organization-domains"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/organizations/:id/domains")
	g.Use(mw.RequireSiteAdminOrSameOrgAdmin("id"))
	// THE-REMAINING-FOUR (2026-08-30): domains are a tenant's own resource —
	// site_admin is refused here (the shared guard admits it for its
	// org-lifecycle neighbours; this gate confines the domains family).
	g.Use(refuseSiteAdminOnTenantResource())

	// docgen:endpoint
	// docgen:surface=organization-domains
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/domains
	// docgen:summary=List an organization's domains (safe projection — never exposes the verification-token hash).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.safeOrganizationDomain
	// docgen:notes=org_admin actor must be a member of the requested org (same-org enforcement via :id path param).
	g.GET("", HandleListOrganizationDomains(deps))

	// docgen:endpoint
	// docgen:surface=organization-domains
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/domains
	// docgen:summary=Add a domain to an organization (issues a verification token whose hash is stored; the raw token is returned ONCE).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.safeOrganizationDomain
	// docgen:notes=Verification token is one-shot — only the SHA-256 hash is persisted; the raw token never appears again after the first response.
	// docgen:status=201
	g.POST("", HandleAddOrganizationDomain(deps))

	// docgen:endpoint
	// docgen:surface=organization-domains
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/domains/:domain_id/verify
	// docgen:summary=Verify a domain by presenting the previously-issued verification token.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.safeOrganizationDomain
	g.POST("/:domain_id/verify", HandleVerifyOrganizationDomain(deps))

	// docgen:endpoint
	// docgen:surface=organization-domains
	// docgen:method=DELETE
	// docgen:path=/api/v1/organizations/:id/domains/:domain_id
	// docgen:summary=Remove a domain from an organization.
	// docgen:tier=oss
	// docgen:auth=org_admin
	g.DELETE("/:domain_id", HandleDeleteOrganizationDomain(deps))

	// docgen:endpoint
	// docgen:surface=organization-domains
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/domains/:domain_id/primary
	// docgen:summary=Set an organization's primary domain.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.safeOrganizationDomain
	g.POST("/:domain_id/primary", HandleSetPrimaryOrganizationDomain(deps))
}

// safeOrganizationDomain is the on-the-wire shape. The hash
// (VerificationTokenHash) is deliberately omitted; the token TTL
// and attempts counter are exposed so an operator can pace
// challenge retries.
type safeOrganizationDomain struct {
	ID                         uuid.UUID  `json:"id"`
	OrganizationID             uuid.UUID  `json:"organization_id"`
	Domain                     string     `json:"domain"`
	IsPrimary                  bool       `json:"is_primary"`
	Verified                   bool       `json:"verified"`
	VerifiedAt                 *time.Time `json:"verified_at,omitempty"`
	VerificationTokenExpiresAt *time.Time `json:"verification_token_expires_at,omitempty"`
	VerificationAttempts       int        `json:"verification_attempts"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
}

func toSafeOrganizationDomain(d *domain.OrganizationDomain) safeOrganizationDomain {
	if d == nil {
		return safeOrganizationDomain{}
	}
	return safeOrganizationDomain{
		ID:                         d.ID,
		OrganizationID:             d.OrganizationID,
		Domain:                     d.Domain,
		IsPrimary:                  d.IsPrimary,
		Verified:                   d.IsVerified(),
		VerifiedAt:                 d.VerifiedAt,
		VerificationTokenExpiresAt: d.VerificationTokenExpiresAt,
		VerificationAttempts:       d.VerificationAttempts,
		CreatedAt:                  d.CreatedAt,
		UpdatedAt:                  d.UpdatedAt,
	}
}

func parseOrgAndDomainID(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
		return uuid.Nil, uuid.Nil, false
	}
	domainID, err := uuid.Parse(c.Param("domain_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain id"})
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, domainID, true
}

// HandleListOrganizationDomains lists every domain row for the
// :id organization.
func HandleListOrganizationDomains(deps OrganizationDomainsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		rows, err := deps.OrganizationDomainService.ListByOrganization(c.Request.Context(), orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeOrganizationDomain, 0, len(rows))
		for _, d := range rows {
			out = append(out, toSafeOrganizationDomain(d))
		}
		c.JSON(http.StatusOK, gin.H{
			"organization_domains": out,
			"count":                len(out),
		})
	}
}

// HandleAddOrganizationDomain creates a pending claim. The raw
// verification token is returned EXACTLY ONCE so the operator can
// publish it as the DNS TXT challenge; only its SHA-256 hex is
// persisted.
func HandleAddOrganizationDomain(deps OrganizationDomainsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		var req struct {
			Domain string `json:"domain"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		row, rawToken, err := deps.OrganizationDomainService.AddOrganizationDomain(c.Request.Context(), orgID, req.Domain)
		if err != nil {
			if errors.Is(err, domain.ErrOrganizationDomainAlreadyExists) ||
				errors.Is(err, domain.ErrOrganizationDomainVerifiedByOther) ||
				errors.Is(err, domain.ErrOrganizationDomainInvalid) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"organization_domain": toSafeOrganizationDomain(row),
			"verification_token":  rawToken,
			"txt_record_name":     "_identuum-challenge." + row.Domain,
			"txt_record_value":    "identuum-domain-verification=" + rawToken,
		})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization_domain.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": orgID, "domain_id": row.ID, "domain": row.Domain},
		})
	}
}

// HandleVerifyOrganizationDomain runs the DNS proof-of-control
// check via the configured DomainProofVerifier.
func HandleVerifyOrganizationDomain(deps OrganizationDomainsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, domainID, ok := parseOrgAndDomainID(c)
		if !ok {
			return
		}
		err := deps.OrganizationDomainService.Verify(c.Request.Context(), domainID, orgID)
		switch {
		case err == nil:
			c.JSON(http.StatusOK, gin.H{"verified": true, "id": domainID})
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "organization_domain.verified",
				Outcome:   "success",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				Metadata:  map[string]any{"organization_id": orgID, "domain_id": domainID},
			})
		case errors.Is(err, service.ErrDomainVerifierUnavailable):
			c.JSON(http.StatusNotImplemented, gin.H{
				"error":     "not implemented",
				"operation": "verify",
				"reason":    "DNS verifier not wired in this build",
			})
		case errors.Is(err, service.ErrDomainTokenAlreadyConsumed):
			c.JSON(http.StatusConflict, gin.H{"error": "no pending verification token"})
		case errors.Is(err, service.ErrDomainTokenExpired):
			c.JSON(http.StatusConflict, gin.H{"error": "verification token expired"})
		case errors.Is(err, service.ErrDomainVerificationRecordNotFound):
			c.JSON(http.StatusBadRequest, gin.H{"error": "txt record not found"})
		case errors.Is(err, service.ErrDomainVerificationMismatch):
			c.JSON(http.StatusBadRequest, gin.H{"error": "txt record does not match expected proof"})
		case errors.Is(err, service.ErrDomainVerificationLookupFailed):
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "dns lookup failed"})
		case errors.Is(err, domain.ErrOrganizationDomainNotFound),
			errors.Is(err, service.ErrOrganizationDomainNotFound()):
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
	}
}

// HandleDeleteOrganizationDomain removes a domain row.
func HandleDeleteOrganizationDomain(deps OrganizationDomainsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, domainID, ok := parseOrgAndDomainID(c)
		if !ok {
			return
		}
		if err := deps.OrganizationDomainService.Delete(c.Request.Context(), domainID, orgID); err != nil {
			// THE-SIXTEEN-ELSES: 404 only for the repo's real-miss
			// sentinel (0 rows affected); unknown faults say so.
			if errors.Is(err, domain.ErrOrganizationDomainNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": domainID})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization_domain.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": orgID, "domain_id": domainID},
		})
	}
}

// HandleSetPrimaryOrganizationDomain promotes the row to primary.
func HandleSetPrimaryOrganizationDomain(deps OrganizationDomainsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, domainID, ok := parseOrgAndDomainID(c)
		if !ok {
			return
		}
		if err := deps.OrganizationDomainService.SetPrimary(c.Request.Context(), domainID, orgID); err != nil {
			// THE-SIXTEEN-ELSES: 404 only for the repo's real-miss
			// sentinel; unknown faults say so.
			if errors.Is(err, domain.ErrOrganizationDomainNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"primary": domainID})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization_domain.set_primary",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": orgID, "domain_id": domainID},
		})
	}
}
