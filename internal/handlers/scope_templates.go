package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ScopeTemplatesHandlerDeps wires the scope-template admin group.
//
// ScopeTemplateService preferred; ScopeTemplateRepo legacy (read-only).
// FeatureGate, when nil, defaults to features.OpenGate; CE composition
// supplies a tier-aware gate.
type ScopeTemplatesHandlerDeps struct {
	ScopeTemplateService *service.ScopeTemplateService
	ScopeTemplateRepo    repository.ScopeTemplateRepository
	Audit                audit.Service
	FeatureGate          features.FeatureGate

	// StartupReport receives a fatal fault if neither service nor repo is
	// wired — instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterScopeTemplatesRoutes wires /api/v1/scope-templates onto
// router.
//
// Implemented:
//
//	GET /api/v1/scope-templates             — list within the actor's org
//	GET /api/v1/scope-templates/:id         — fetch by id
//
// Deferred (501):
//
//	POST   /api/v1/scope-templates
//	PUT    /api/v1/scope-templates/:id
//	DELETE /api/v1/scope-templates/:id
//
// The monolith routes are gated on the AuthorizationServer feature
// (Commercial tier). The OSS scaffold does not yet wire feature
// gates; future CE composition can add the gate layer on top.
//
// Read scope: the OSS ScopeTemplateRepository requires an orgID
// for List and GetByID. The handler reads OrganizationID from the
// authenticated principal. A nil-org principal (site-admin without
// a tenant association) currently 400s instead of falling back to
// a cross-tenant list — that behaviour difference vs the monolith
// is documented.
func RegisterScopeTemplatesRoutes(router gin.IRouter, deps ScopeTemplatesHandlerDeps) {
	if deps.ScopeTemplateService == nil && deps.ScopeTemplateRepo == nil {
		// P-018: scope templates govern OAuth scope issuance — token-path
		// critical. FATAL. Record the fault + mount a service-missing
		// fallback instead of panicking.
		deps.StartupReport.Fatal(
			"scope-templates-routes",
			"scope-templates admin surface unavailable: neither ScopeTemplateService nor ScopeTemplateRepo is wired",
		)
		g := router.Group("/api/v1/scope-templates")
		g.GET("", serviceMissingFallback("scope-templates"))
		g.GET("/:id", serviceMissingFallback("scope-templates"))
		g.POST("", serviceMissingFallback("scope-templates"))
		g.PUT("/:id", serviceMissingFallback("scope-templates"))
		g.DELETE("/:id", serviceMissingFallback("scope-templates"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/scope-templates")
	// Commercial-feature gate (monolith: features.AuthorizationServer).
	// Audit-aware variant: a denial emits `feature.denied` when an
	// audit.Service is wired.
	g.Use(mw.RequireFeatureWithAudit(deps.FeatureGate, deps.Audit, features.AuthorizationServer))
	g.Use(mw.RequireSiteAdmin())

	// docgen:endpoint
	// docgen:surface=scope-templates
	// docgen:method=GET
	// docgen:path=/api/v1/scope-templates
	// docgen:summary=List scope templates for the authenticated principal's organization (Authorization Server feature).
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=site_admin
	// docgen:feature_gate=authorization_server
	// docgen:response=oss.handlers.safeScopeTemplate
	// docgen:notes=Nil-org principal currently 400s rather than cross-tenant listing (documented difference vs the monolith).
	g.GET("", HandleListScopeTemplates(deps))

	// docgen:endpoint
	// docgen:surface=scope-templates
	// docgen:method=GET
	// docgen:path=/api/v1/scope-templates/:id
	// docgen:summary=Show a single scope template by id (Authorization Server feature).
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=site_admin
	// docgen:feature_gate=authorization_server
	// docgen:response=oss.handlers.safeScopeTemplate
	g.GET("/:id", HandleGetScopeTemplate(deps))

	if deps.ScopeTemplateService != nil {
		// docgen:endpoint
		// docgen:surface=scope-templates
		// docgen:method=POST
		// docgen:path=/api/v1/scope-templates
		// docgen:summary=Create a scope template (Authorization Server feature).
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		// docgen:response=oss.handlers.safeScopeTemplate
		// docgen:status=201
		g.POST("", HandleCreateScopeTemplate(deps))

		// docgen:endpoint
		// docgen:surface=scope-templates
		// docgen:method=PUT
		// docgen:path=/api/v1/scope-templates/:id
		// docgen:summary=Update a scope template (Authorization Server feature).
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		// docgen:response=oss.handlers.safeScopeTemplate
		g.PUT("/:id", HandleUpdateScopeTemplate(deps))

		// docgen:endpoint
		// docgen:surface=scope-templates
		// docgen:method=DELETE
		// docgen:path=/api/v1/scope-templates/:id
		// docgen:summary=Delete a scope template (Authorization Server feature).
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		g.DELETE("/:id", HandleDeleteScopeTemplate(deps))
	} else {
		g.POST("", scopeTemplateServiceMissing("create"))
		g.PUT("/:id", scopeTemplateServiceMissing("update"))
		g.DELETE("/:id", scopeTemplateServiceMissing("delete"))
	}
}

type safeScopeTemplate struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	Scopes         []string  `json:"scopes"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func toSafeScopeTemplate(t *domain.ScopeTemplate) safeScopeTemplate {
	if t == nil {
		return safeScopeTemplate{}
	}
	scopes := append([]string(nil), t.Scopes...)
	return safeScopeTemplate{
		ID:             t.ID,
		OrganizationID: t.OrganizationID,
		Name:           t.Name,
		Description:    t.Description,
		Scopes:         scopes,
		CreatedAt:      t.CreatedAt,
		UpdatedAt:      t.UpdatedAt,
	}
}

// HandleListScopeTemplates lists templates scoped to the principal's
// OrganizationID.
func HandleListScopeTemplates(deps ScopeTemplatesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		var (
			templates []*domain.ScopeTemplate
			err       error
		)
		if deps.ScopeTemplateService != nil {
			templates, err = deps.ScopeTemplateService.List(c.Request.Context(), p.OrganizationID)
		} else {
			templates, err = deps.ScopeTemplateRepo.List(c.Request.Context(), p.OrganizationID)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeScopeTemplate, 0, len(templates))
		for _, t := range templates {
			out = append(out, toSafeScopeTemplate(t))
		}
		c.JSON(http.StatusOK, gin.H{
			"scope_templates": out,
			"count":           len(out),
		})
	}
}

// HandleGetScopeTemplate returns a single template by UUID id
// scoped to the principal's OrganizationID.
func HandleGetScopeTemplate(deps ScopeTemplatesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var t *domain.ScopeTemplate
		if deps.ScopeTemplateService != nil {
			t, err = deps.ScopeTemplateService.GetByID(c.Request.Context(), id, p.OrganizationID)
		} else {
			t, err = deps.ScopeTemplateRepo.GetByID(c.Request.Context(), id, p.OrganizationID)
		}
		if err != nil || t == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeScopeTemplate(t))
	}
}

// HandleCreateScopeTemplate creates a new scope template scoped to
// the principal's OrganizationID.
func HandleCreateScopeTemplate(deps ScopeTemplatesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description,omitempty"`
			Scopes      []string `json:"scopes"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		template, err := deps.ScopeTemplateService.Create(c.Request.Context(), service.CreateScopeTemplateOptions{
			OrganizationID: p.OrganizationID,
			Name:           req.Name,
			Description:    req.Description,
			Scopes:         req.Scopes,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, toSafeScopeTemplate(template))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "scope_template.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"template_id": template.ID, "name": template.Name},
		})
	}
}

// HandleUpdateScopeTemplate mutates a template scoped to the
// principal's OrganizationID.
func HandleUpdateScopeTemplate(deps ScopeTemplatesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Name        string   `json:"name,omitempty"`
			Description string   `json:"description,omitempty"`
			Scopes      []string `json:"scopes,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		template, err := deps.ScopeTemplateService.Update(c.Request.Context(), id, p.OrganizationID, service.UpdateScopeTemplateOptions{
			Name:        req.Name,
			Description: req.Description,
			Scopes:      req.Scopes,
		})
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeScopeTemplate(template))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "scope_template.updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"template_id": template.ID},
		})
	}
}

// HandleDeleteScopeTemplate removes a template scoped to the
// principal's OrganizationID.
func HandleDeleteScopeTemplate(deps ScopeTemplatesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := deps.ScopeTemplateService.Delete(c.Request.Context(), id, p.OrganizationID); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "scope_template.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"template_id": id},
		})
	}
}

func scopeTemplateServiceMissing(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":     "not implemented",
			"operation": op,
			"reason":    "ScopeTemplateService not yet relocated into the OSS module; " + op + " requires service-layer validation.",
		})
	}
}
