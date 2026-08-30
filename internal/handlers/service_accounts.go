package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/types"
)

// ServiceAccountsHandlerDeps wires the /api/v1/.../service-accounts
// admin group.
type ServiceAccountsHandlerDeps struct {
	ServiceAccountService *service.ServiceAccountService
	Audit                 audit.Service
}

// RegisterServiceAccountsRoutes mounts:
//
//	GET    /api/v1/organizations/:id/service-accounts
//	POST   /api/v1/organizations/:id/service-accounts
//	GET    /api/v1/service-accounts/:id
//	PUT    /api/v1/service-accounts/:id
//	DELETE /api/v1/service-accounts/:id
//	POST   /api/v1/service-accounts/:id/enable
//	POST   /api/v1/service-accounts/:id/disable
//
// Every route requires authentication. The HTTP layer enforces
// site_admin OR org_admin gates; the service layer enforces
// same-tenant authority (defense in depth). All routes register
// ONLY when ServiceAccountService is non-nil.
func RegisterServiceAccountsRoutes(router gin.IRouter, deps ServiceAccountsHandlerDeps) {
	if deps.ServiceAccountService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// Org-scoped routes.
	orgGroup := router.Group("/api/v1/organizations/:id/service-accounts")
	orgGroup.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/service-accounts
	// docgen:summary=List service accounts in an organization (service enforces site_admin OR the org's own org_admin).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced in ServiceAccountService.requireOrgAdmin (actor must be site_admin OR the requested org's own org_admin — plain same-org membership is refused; a foreign org's org_admin reads not-found).
	orgGroup.GET("", HandleListServiceAccounts(deps))

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/service-accounts
	// docgen:summary=Create a service account in an organization (service enforces site_admin OR the org's own org_admin).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	// docgen:status=201
	orgGroup.POST("", HandleCreateServiceAccount(deps))

	// ID-scoped routes.
	saGroup := router.Group("/api/v1/service-accounts/:id")
	saGroup.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=GET
	// docgen:path=/api/v1/service-accounts/:id
	// docgen:summary=Show a service account (handler enforces site_admin OR same-org membership).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	saGroup.GET("", HandleGetServiceAccount(deps))

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=PUT
	// docgen:path=/api/v1/service-accounts/:id
	// docgen:summary=Update a service account (handler enforces site_admin OR same-org membership).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	saGroup.PUT("", HandleUpdateServiceAccount(deps))

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=DELETE
	// docgen:path=/api/v1/service-accounts/:id
	// docgen:summary=Delete a service account (handler enforces site_admin OR same-org membership).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	// docgen:status=204
	saGroup.DELETE("", HandleDeleteServiceAccount(deps))

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=POST
	// docgen:path=/api/v1/service-accounts/:id/enable
	// docgen:summary=Enable a previously-disabled service account (handler enforces site_admin OR same-org membership).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	// docgen:status=204
	saGroup.POST("/enable", HandleSetActiveServiceAccount(deps, true))

	// docgen:endpoint
	// docgen:surface=service-accounts
	// docgen:method=POST
	// docgen:path=/api/v1/service-accounts/:id/disable
	// docgen:summary=Disable a service account (handler enforces site_admin OR same-org membership).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Authorisation is enforced at the handler layer.
	// docgen:status=204
	saGroup.POST("/disable", HandleSetActiveServiceAccount(deps, false))
}

// HandleListServiceAccounts lists SAs in the supplied organization.
func HandleListServiceAccounts(deps ServiceAccountsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		orgID, ok := parseSAOrgID(c)
		if !ok {
			return
		}
		sas, err := deps.ServiceAccountService.ListForActor(c.Request.Context(), actor, orgID)
		if err != nil {
			respondSAError(c, err)
			return
		}
		c.JSON(http.StatusOK, toSafeServiceAccounts(sas))
	}
}

// HandleCreateServiceAccount creates a new SA in the supplied
// organization.
func HandleCreateServiceAccount(deps ServiceAccountsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		orgID, ok := parseSAOrgID(c)
		if !ok {
			return
		}
		var req serviceAccountCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		sa, err := deps.ServiceAccountService.CreateForActor(c.Request.Context(), actor, orgID, service.ServiceAccountAdminInput{
			Name:        req.Name,
			Description: req.Description,
			Role:        domain.UserRole(req.Role),
			ExpiresAt:   req.ExpiresAt,
		})
		if err != nil {
			respondSAError(c, err)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "service_account.created",
			Outcome:        "success",
			SubjectID:      sa.ID,
			SubjectType:    "service_account",
			OrganizationID: sa.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"service_account_id": sa.ID.String(),
				"organization_id":    sa.OrganizationID.String(),
				"role":               string(sa.Role),
			},
		}))
		c.JSON(http.StatusCreated, toSafeServiceAccount(sa))
	}
}

// HandleGetServiceAccount returns one SA by ID.
func HandleGetServiceAccount(deps ServiceAccountsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		saID, ok := parseSAID(c)
		if !ok {
			return
		}
		sa, err := deps.ServiceAccountService.GetForActor(c.Request.Context(), actor, saID)
		if err != nil {
			respondSAError(c, err)
			return
		}
		c.JSON(http.StatusOK, toSafeServiceAccount(sa))
	}
}

// HandleUpdateServiceAccount mutates name / description / role /
// expires_at.
func HandleUpdateServiceAccount(deps ServiceAccountsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		saID, ok := parseSAID(c)
		if !ok {
			return
		}
		var req serviceAccountUpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		sa, err := deps.ServiceAccountService.UpdateForActor(c.Request.Context(), actor, saID, service.ServiceAccountAdminInput{
			Name:        req.Name,
			Description: req.Description,
			Role:        domain.UserRole(req.Role),
			ExpiresAt:   req.ExpiresAt,
		})
		if err != nil {
			respondSAError(c, err)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "service_account.updated",
			Outcome:        "success",
			SubjectID:      sa.ID,
			SubjectType:    "service_account",
			OrganizationID: sa.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"service_account_id": sa.ID.String(),
				"organization_id":    sa.OrganizationID.String(),
			},
		}))
		c.JSON(http.StatusOK, toSafeServiceAccount(sa))
	}
}

// HandleDeleteServiceAccount soft-deletes the SA.
func HandleDeleteServiceAccount(deps ServiceAccountsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		saID, ok := parseSAID(c)
		if !ok {
			return
		}
		// The row is gone after the delete — read its tenant org first (via
		// the same actor-scoped read the delete itself performs) so the audit
		// event lands in the right trail.
		var saOrg uuid.UUID
		if prior, perr := deps.ServiceAccountService.GetForActor(c.Request.Context(), actor, saID); perr == nil && prior != nil {
			saOrg = prior.OrganizationID
		}
		if err := deps.ServiceAccountService.DeleteForActor(c.Request.Context(), actor, saID); err != nil {
			respondSAError(c, err)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "service_account.deleted",
			Outcome:        "success",
			SubjectID:      saID,
			SubjectType:    "service_account",
			OrganizationID: saOrg,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"service_account_id": saID.String(),
			},
		}))
		c.Status(http.StatusNoContent)
	}
}

// HandleSetActiveServiceAccount flips the active flag.
func HandleSetActiveServiceAccount(deps ServiceAccountsHandlerDeps, active bool) gin.HandlerFunc {
	action := "service_account.disabled"
	if active {
		action = "service_account.enabled"
	}
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		saID, ok := parseSAID(c)
		if !ok {
			return
		}
		if err := deps.ServiceAccountService.SetActiveForActor(c.Request.Context(), actor, saID, active); err != nil {
			respondSAError(c, err)
			return
		}
		// Same actor-scoped read the toggle itself performed — the event must
		// land in the SA's tenant trail (v0.3.2 Order A).
		var saOrg uuid.UUID
		if sa, gerr := deps.ServiceAccountService.GetForActor(c.Request.Context(), actor, saID); gerr == nil && sa != nil {
			saOrg = sa.OrganizationID
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         action,
			Outcome:        "success",
			SubjectID:      saID,
			SubjectType:    "service_account",
			OrganizationID: saOrg,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"service_account_id": saID.String(),
			},
		}))
		c.Status(http.StatusNoContent)
	}
}

// ---------- Request DTOs ----------

type serviceAccountCreateRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Role        string     `json:"role"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type serviceAccountUpdateRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Role        string     `json:"role"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// ---------- DTO mapping ----------

func toSafeServiceAccount(sa *domain.ServiceAccount) types.ServiceAccount {
	if sa == nil {
		return types.ServiceAccount{}
	}
	return types.ServiceAccount{
		ID:             sa.ID,
		OrganizationID: sa.OrganizationID,
		Name:           sa.Name,
		Description:    sa.Description,
		Role:           string(sa.Role),
		Active:         sa.Active,
		ExpiresAt:      sa.ExpiresAt,
		CreatedAt:      sa.CreatedAt,
		UpdatedAt:      sa.UpdatedAt,
	}
}

func toSafeServiceAccounts(sas []*domain.ServiceAccount) []types.ServiceAccount {
	out := make([]types.ServiceAccount, 0, len(sas))
	for _, sa := range sas {
		out = append(out, toSafeServiceAccount(sa))
	}
	return out
}

// ---------- helpers ----------

func parseSAOrgID(c *gin.Context) (uuid.UUID, bool) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
		return uuid.Nil, false
	}
	return orgID, true
}

func parseSAID(c *gin.Context) (uuid.UUID, bool) {
	saID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service account id"})
		return uuid.Nil, false
	}
	return saID, true
}

func respondSAError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrSAForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, service.ErrSANotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, service.ErrSAInvalidInput),
		errors.Is(err, service.ErrSARoleInvalid),
		errors.Is(err, service.ErrSAExpiryInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
	case errors.Is(err, domain.ErrServiceAccountNameTaken):
		// Migration 0030's per-org live-name unique index (gap E) — the UI
		// renders this as an inline name-field conflict.
		c.JSON(http.StatusConflict, gin.H{
			"error":   "name_taken",
			"message": "A service account with this name already exists in this organization.",
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}
