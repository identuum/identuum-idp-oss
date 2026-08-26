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

// APIResourcesHandlerDeps wires the API-resource admin group.
//
// APIResourceService preferred; APIResourceRepo legacy (read-only).
// FeatureGate, when nil, defaults to features.OpenGate so the
// scaffold does not regress route reachability; CE composition
// supplies a tier-aware gate.
type APIResourcesHandlerDeps struct {
	APIResourceService *service.APIResourceService
	APIResourceRepo    repository.APIResourceRepository
	Audit              audit.Service
	FeatureGate        features.FeatureGate

	// StartupReport receives a fatal fault if neither APIResourceService
	// nor APIResourceRepo is wired — instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterAPIResourcesRoutes wires /api/v1/api-resources onto router.
//
// Implemented:
//
//	GET /api/v1/api-resources
//	GET /api/v1/api-resources/:id
//
// Deferred (501):
//
//	POST   /api/v1/api-resources
//	PUT    /api/v1/api-resources/:id
//	DELETE /api/v1/api-resources/:id
//	POST   /api/v1/api-resources/:id/secret/regenerate
//
// The monolith routes are gated on the AuthorizationServer feature
// flag. OSS does not yet wire feature gates; for now the read
// surface is open to any site-admin caller. Future CE composition
// can add the feature gate layer on top.
func RegisterAPIResourcesRoutes(router gin.IRouter, deps APIResourcesHandlerDeps) {
	if deps.APIResourceService == nil && deps.APIResourceRepo == nil {
		// P-018: api-resources defines token audiences/scopes — on the
		// authorization/token path. FATAL. Record the fault and mount a
		// uniform service-missing fallback instead of panicking.
		deps.StartupReport.Fatal(
			"api-resources-routes",
			"api-resources admin surface unavailable: neither APIResourceService nor APIResourceRepo is wired",
		)
		g := router.Group("/api/v1/api-resources")
		g.GET("", serviceMissingFallback("api-resources"))
		g.GET("/:id", serviceMissingFallback("api-resources"))
		g.POST("", serviceMissingFallback("api-resources"))
		g.PUT("/:id", serviceMissingFallback("api-resources"))
		g.DELETE("/:id", serviceMissingFallback("api-resources"))
		g.POST("/:id/secret/regenerate", serviceMissingFallback("api-resources"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/api-resources")
	// Commercial-feature gate (monolith: features.AuthorizationServer).
	// Mounted BEFORE RequireSiteAdmin so a deny short-circuits with
	// 403 before any auth decision is made. The audit-aware variant
	// is used so a denial emits a safe `feature.denied` event when
	// an audit.Service is wired.
	g.Use(mw.RequireFeatureWithAudit(deps.FeatureGate, deps.Audit, features.AuthorizationServer))
	g.Use(mw.RequireSiteAdmin())

	// docgen:endpoint
	// docgen:surface=api-resources
	// docgen:method=GET
	// docgen:path=/api/v1/api-resources
	// docgen:summary=List API resources (Authorization Server feature).
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=site_admin
	// docgen:feature_gate=authorization_server
	// docgen:response=oss.handlers.safeAPIResource
	g.GET("", HandleListAPIResources(deps))

	// docgen:endpoint
	// docgen:surface=api-resources
	// docgen:method=GET
	// docgen:path=/api/v1/api-resources/:id
	// docgen:summary=Show a single API resource.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=site_admin
	// docgen:feature_gate=authorization_server
	// docgen:response=oss.handlers.safeAPIResource
	g.GET("/:id", HandleGetAPIResource(deps))

	if deps.APIResourceService != nil {
		// docgen:endpoint
		// docgen:surface=api-resources
		// docgen:method=POST
		// docgen:path=/api/v1/api-resources
		// docgen:summary=Create an API resource.
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		// docgen:response=oss.handlers.safeAPIResource
		// docgen:status=201
		g.POST("", HandleCreateAPIResource(deps))

		// docgen:endpoint
		// docgen:surface=api-resources
		// docgen:method=PUT
		// docgen:path=/api/v1/api-resources/:id
		// docgen:summary=Update an API resource.
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		// docgen:response=oss.handlers.safeAPIResource
		g.PUT("/:id", HandleUpdateAPIResource(deps))

		// docgen:endpoint
		// docgen:surface=api-resources
		// docgen:method=DELETE
		// docgen:path=/api/v1/api-resources/:id
		// docgen:summary=Delete an API resource.
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		g.DELETE("/:id", HandleDeleteAPIResource(deps))

		// docgen:endpoint
		// docgen:surface=api-resources
		// docgen:method=POST
		// docgen:path=/api/v1/api-resources/:id/secret/regenerate
		// docgen:summary=Rotate an API resource secret (new secret returned ONCE; never stored or echoed elsewhere).
		// docgen:tier=oss-feature-gated:authorization_server
		// docgen:auth=site_admin
		// docgen:feature_gate=authorization_server
		g.POST("/:id/secret/regenerate", HandleRegenerateAPIResourceSecret(deps))
	} else {
		g.POST("", apiResourceServiceMissing("create"))
		g.PUT("/:id", apiResourceServiceMissing("update"))
		g.DELETE("/:id", apiResourceServiceMissing("delete"))
		g.POST("/:id/secret/regenerate", apiResourceServiceMissing("secret rotation"))
	}
}

// safeAPIResource omits ResourceSecretHash so the JSON response
// never carries hashed secret material on the wire.
type safeAPIResource struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID uuid.UUID      `json:"organization_id"`
	Name           string         `json:"name"`
	Audience       string         `json:"audience"`
	Active         bool           `json:"active"`
	TokenTTLSecs   int            `json:"token_ttl_secs"`
	Scopes         []safeAPIScope `json:"scopes"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type safeAPIScope struct {
	ID          uuid.UUID `json:"id"`
	ResourceID  uuid.UUID `json:"resource_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
}

func toSafeAPIResource(r *domain.APIResource) safeAPIResource {
	out := safeAPIResource{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Name:           r.Name,
		Audience:       r.Audience,
		Active:         r.Active,
		TokenTTLSecs:   r.TokenTTLSecs,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		Scopes:         make([]safeAPIScope, 0, len(r.Scopes)),
	}
	for _, s := range r.Scopes {
		out.Scopes = append(out.Scopes, safeAPIScope{
			ID:          s.ID,
			ResourceID:  s.ResourceID,
			Name:        s.Name,
			Description: s.Description,
		})
	}
	return out
}

// HandleListAPIResources returns the paginated list of API resources
// in safe-projection form.
func HandleListAPIResources(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		pageSize := parsePositiveQuery(c, "page_size", 50, 200)
		page := parsePositiveQuery(c, "page", 1, 1<<16)
		pagination := repository.Pagination{
			Page:     page,
			PageSize: pageSize,
			Offset:   (page - 1) * pageSize,
		}
		var (
			resources []*domain.APIResource
			total     int
			err       error
		)
		if deps.APIResourceService != nil {
			resources, total, err = deps.APIResourceService.List(c.Request.Context(), pagination, nil)
		} else {
			resources, total, err = deps.APIResourceRepo.List(c.Request.Context(), pagination, nil)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeAPIResource, 0, len(resources))
		for _, r := range resources {
			out = append(out, toSafeAPIResource(r))
		}
		c.JSON(http.StatusOK, gin.H{
			"api_resources": out,
			"total":         total,
			"page":          page,
			"page_size":     pageSize,
		})
	}
}

// HandleGetAPIResource returns a single API resource by UUID id.
func HandleGetAPIResource(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var resource *domain.APIResource
		if deps.APIResourceService != nil {
			resource, err = deps.APIResourceService.GetByID(c.Request.Context(), id, nil)
		} else {
			resource, err = deps.APIResourceRepo.GetByID(c.Request.Context(), id, nil)
		}
		if err != nil || resource == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeAPIResource(resource))
	}
}

// HandleCreateAPIResource creates a new API resource + scope set.
// Returns the safe projection plus a one-time plaintext resource
// secret.
func HandleCreateAPIResource(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			OrganizationID uuid.UUID `json:"organization_id"`
			Name           string    `json:"name"`
			Audience       string    `json:"audience"`
			// Active is a POINTER so absence is distinguishable from an
			// explicit false: the UI create body never sends active, and
			// the old bare bool birthed every UI-created API resource
			// deactivated (ABSENT-BOOL-1, the BORN-ACTIVE-1 shape).
			Active       *bool             `json:"active,omitempty"`
			TokenTTLSecs int               `json:"token_ttl_secs"`
			Scopes       []domain.APIScope `json:"scopes,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		resource, plaintext, err := deps.APIResourceService.Create(c.Request.Context(), service.CreateAPIResourceOptions{
			OrganizationID: req.OrganizationID,
			Name:           req.Name,
			Audience:       req.Audience,
			Active:         req.Active == nil || *req.Active,
			TokenTTLSecs:   req.TokenTTLSecs,
			Scopes:         req.Scopes,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"api_resource":    toSafeAPIResource(resource),
			"resource_secret": plaintext,
		})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "api_resource.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"resource_id": resource.ID,
				"audience":    resource.Audience,
			},
		})
	}
}

// HandleUpdateAPIResource mutates a resource.
func HandleUpdateAPIResource(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Name         *string           `json:"name,omitempty"`
			Audience     *string           `json:"audience,omitempty"`
			Active       *bool             `json:"active,omitempty"`
			TokenTTLSecs *int              `json:"token_ttl_secs,omitempty"`
			Scopes       []domain.APIScope `json:"scopes,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		resource, err := deps.APIResourceService.Update(c.Request.Context(), id, service.UpdateAPIResourceOptions{
			Name:         req.Name,
			Audience:     req.Audience,
			Active:       req.Active,
			TokenTTLSecs: req.TokenTTLSecs,
			Scopes:       req.Scopes,
		})
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeAPIResource(resource))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "api_resource.updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"resource_id": resource.ID},
		})
	}
}

// HandleDeleteAPIResource removes a resource.
func HandleDeleteAPIResource(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := deps.APIResourceService.Delete(c.Request.Context(), id, nil); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "api_resource.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"resource_id": id},
		})
	}
}

// HandleRegenerateAPIResourceSecret rotates the resource secret.
func HandleRegenerateAPIResourceSecret(deps APIResourcesHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		resource, plaintext, err := deps.APIResourceService.RegenerateSecret(c.Request.Context(), id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"api_resource":    toSafeAPIResource(resource),
			"resource_secret": plaintext,
		})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "api_resource.secret_rotated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"resource_id": resource.ID},
		})
	}
}

func apiResourceServiceMissing(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":     "not implemented",
			"operation": op,
			"reason":    "APIResourceService not yet relocated into the OSS module; " + op + " requires scope-set transaction logic.",
		})
	}
}
