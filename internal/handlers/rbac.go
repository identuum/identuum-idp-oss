package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/features"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RBACHandlerDeps wires the OSS RBAC route family. Three groups
// register at the router level:
//
//   - /api/v1/me/roles                                    (caller's own roles)
//   - /api/v1/organizations/:id/roles[/...]               (per-org role CRUD + scopes)
//   - /api/v1/users/:id/roles[/...]                       (user→role assignments)
//
// All three groups are gated by `features.AuthorizationServer` so
// CE composition can flip them on or off based on tier.
//
// OrgRoleService is required. Audit defaults to NoopService.
// FeatureGate defaults to OpenGate.
type RBACHandlerDeps struct {
	OrgRoleService *service.OrgRoleService
	Audit          audit.Service
	FeatureGate    features.FeatureGate

	// StartupReport threads the P-018 NOT-SERVING fault accumulator into
	// the org-scoped authz guard factories. Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterRBACRoutes mounts every RBAC route group under the
// supplied router. Each group registers only when OrgRoleService is
// non-nil; otherwise no routes are added and the paths 404. This
// keeps a deployment that does not yet wire DB-backed repositories
// from accidentally exposing scaffold-only RBAC routes.
//
// Authority model (mirrors the monolith):
//
//	GET /me/roles                                    — any authenticated principal
//	POST   /organizations/:id/roles                  — site_admin OR same-org org_admin w/ orgs:update
//	GET    /organizations/:id/roles                  — site_admin OR same-org org_admin w/ orgs:read
//	GET    /organizations/:id/roles/:role_id         — site_admin OR same-org org_admin w/ orgs:read
//	PUT    /organizations/:id/roles/:role_id         — site_admin OR same-org org_admin w/ orgs:update
//	DELETE /organizations/:id/roles/:role_id         — site_admin OR same-org org_admin w/ orgs:update
//	POST   /organizations/:id/roles/:role_id/scopes  — site_admin OR same-org org_admin w/ orgs:update
//	DELETE /organizations/:id/roles/:role_id/scopes/:scope_name
//	                                                 — site_admin OR same-org org_admin w/ orgs:update
//	GET    /users/:id/roles                          — site_admin OR org_admin w/ users:read
//	                                                  (service layer enforces tenant filter)
//	POST   /users/:id/roles                          — site_admin OR org_admin w/ orgs:update
//	                                                  (service layer enforces tenant)
//	DELETE /users/:id/roles/:role_id                 — site_admin OR org_admin w/ orgs:update
func RegisterRBACRoutes(router gin.IRouter, deps RBACHandlerDeps) {
	if deps.OrgRoleService == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// /me/roles — any authenticated principal can read their own roles.
	mine := router.Group("/api/v1/me/roles")
	mine.Use(mw.RequireFeatureWithAudit(deps.FeatureGate, deps.Audit, features.AuthorizationServer))
	mine.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=GET
	// docgen:path=/api/v1/me/roles
	// docgen:summary=List the authenticated principal's own role assignments (Authorization Server feature).
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=authenticated
	// docgen:feature_gate=authorization_server
	mine.GET("", HandleListMyRoles(deps))

	// /organizations/:id/roles[/...] — org-scoped role CRUD + scopes.
	orgRoles := router.Group("/api/v1/organizations/:id/roles")
	orgRoles.Use(mw.RequireFeatureWithAudit(deps.FeatureGate, deps.Audit, features.AuthorizationServer))
	// THE-REMAINING-FOUR (2026-08-30): org RBAC roles are a tenant's own
	// resource — site_admin is refused for the whole surface.
	orgRoles.Use(refuseSiteAdminOnTenantResource())

	orgRolesRead := orgRoles.Group("")
	orgRolesRead.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeOrgsRead))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/roles
	// docgen:summary=List roles defined in an organization (Authorization Server feature).
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:read scope.
	orgRolesRead.GET("", HandleListOrgRoles(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/roles/:role_id
	// docgen:summary=Show a single org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:read scope.
	orgRolesRead.GET("/:role_id", HandleGetOrgRole(deps))

	orgRolesWrite := orgRoles.Group("")
	orgRolesWrite.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeOrgsUpdate))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/roles
	// docgen:summary=Create an org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:update scope.
	// docgen:status=201
	orgRolesWrite.POST("", HandleCreateOrgRole(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=PUT
	// docgen:path=/api/v1/organizations/:id/roles/:role_id
	// docgen:summary=Update an org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:update scope.
	orgRolesWrite.PUT("/:role_id", HandleUpdateOrgRole(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=DELETE
	// docgen:path=/api/v1/organizations/:id/roles/:role_id
	// docgen:summary=Delete an org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:update scope.
	orgRolesWrite.DELETE("/:role_id", HandleDeleteOrgRole(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/roles/:role_id/scopes
	// docgen:summary=Add a scope to an org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:update scope.
	orgRolesWrite.POST("/:role_id/scopes", HandleAddRoleScope(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=DELETE
	// docgen:path=/api/v1/organizations/:id/roles/:role_id/scopes/:scope_name
	// docgen:summary=Remove a scope from an org role.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor must be a member of the requested org AND carry the orgs:update scope.
	orgRolesWrite.DELETE("/:role_id/scopes/:scope_name", HandleRemoveRoleScope(deps))

	// /users/:id/roles[/...] — user-role bindings.
	userRoles := router.Group("/api/v1/users/:id/roles")
	userRoles.Use(mw.RequireFeatureWithAudit(deps.FeatureGate, deps.Audit, features.AuthorizationServer))
	// THE-REMAINING-FOUR (2026-08-30): user-role bindings are tenant RBAC —
	// site_admin is refused (the service's ListRolesForUserForActor /
	// AssignRoleToUserForActor admitted it via their IsSiteAdmin branches;
	// this HTTP gate confines the surface without touching those shared
	// service methods).
	userRoles.Use(refuseSiteAdminOnTenantResource())

	userRolesRead := userRoles.Group("")
	userRolesRead.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersRead))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=GET
	// docgen:path=/api/v1/users/:id/roles
	// docgen:summary=List a user's role assignments.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor additionally requires the users:read scope.
	userRolesRead.GET("", HandleListRolesForUser(deps))

	userRolesWrite := userRoles.Group("")
	userRolesWrite.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeOrgsUpdate))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=POST
	// docgen:path=/api/v1/users/:id/roles
	// docgen:summary=Assign a role to a user.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor additionally requires the orgs:update scope.
	userRolesWrite.POST("", HandleAssignRoleToUser(deps))

	// docgen:endpoint
	// docgen:surface=rbac
	// docgen:method=DELETE
	// docgen:path=/api/v1/users/:id/roles/:role_id
	// docgen:summary=Remove a role from a user.
	// docgen:tier=oss-feature-gated:authorization_server
	// docgen:auth=org_admin
	// docgen:feature_gate=authorization_server
	// docgen:notes=org_admin actor additionally requires the orgs:update scope.
	userRolesWrite.DELETE("/:role_id", HandleRemoveRoleFromUser(deps))
}

// safeOrgRole is the on-the-wire role shape. domain.OrgRole has no
// secret-bearing fields today; the projection exists so a future
// field added to the domain type that IS sensitive is omitted by
// default rather than leaking.
type safeOrgRole struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"organization_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toSafeOrgRole(r *domain.OrgRole) safeOrgRole {
	if r == nil {
		return safeOrgRole{}
	}
	scopes := append([]string(nil), r.Scopes...)
	return safeOrgRole{
		ID:          r.ID,
		OrgID:       r.OrgID,
		Name:        r.Name,
		Description: r.Description,
		Scopes:      scopes,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func principalForCtx(c *gin.Context) (*domain.Principal, bool) {
	p, ok := mw.PrincipalFromContext(c)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

// HandleListMyRoles returns the caller's own role assignments.
func HandleListMyRoles(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, ok := principalForCtx(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		roles, err := deps.OrgRoleService.ListMyRoles(c.Request.Context(), actor)
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeOrgRole, 0, len(roles))
		for _, r := range roles {
			out = append(out, toSafeOrgRole(r))
		}
		c.JSON(http.StatusOK, gin.H{"roles": out, "count": len(out)})
	}
}

// HandleCreateOrgRole creates a role in the :id organization.
func HandleCreateOrgRole(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		actor, _ := principalForCtx(c)
		role, err := deps.OrgRoleService.CreateRoleForActor(c.Request.Context(), actor, orgID, req.Name, req.Description)
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, toSafeOrgRole(role))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"role_id":         role.ID,
				"organization_id": role.OrgID,
				"name":            role.Name,
			},
		})
	}
}

// HandleListOrgRoles lists roles for the :id organization.
func HandleListOrgRoles(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
			return
		}
		actor, _ := principalForCtx(c)
		roles, err := deps.OrgRoleService.ListRolesForActor(c.Request.Context(), actor, orgID)
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeOrgRole, 0, len(roles))
		for _, r := range roles {
			out = append(out, toSafeOrgRole(r))
		}
		c.JSON(http.StatusOK, gin.H{"roles": out, "count": len(out)})
	}
}

// HandleGetOrgRole returns a single role by id.
func HandleGetOrgRole(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		actor, _ := principalForCtx(c)
		role, err := deps.OrgRoleService.GetRoleForActor(c.Request.Context(), actor, roleID)
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			// THE-SIXTEEN-ELSES: 404 only for the real miss.
			if errors.Is(err, service.ErrOrgRoleNotFound()) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, toSafeOrgRole(role))
	}
}

// HandleUpdateOrgRole updates name/description for an existing role.
func HandleUpdateOrgRole(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		// THE-SILENT-DROP: POINTERS, so absent and supplied-blank are
		// distinguishable on the wire. As plain strings they were not, and a
		// blank rename was dropped and answered 200.
		var req struct {
			Name        *string `json:"name,omitempty"`
			Description *string `json:"description,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		actor, _ := principalForCtx(c)
		role, err := deps.OrgRoleService.UpdateRoleForActor(c.Request.Context(), actor, roleID, service.UpdateOrgRoleOptions{
			Name:        req.Name,
			Description: req.Description,
		})
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			// THE-SIXTEEN-ELSES: 404 only for the real miss; a rename
			// into UNIQUE (org_id, name) is an honest 409; unknown
			// faults say so.
			switch {
			case errors.Is(err, service.ErrOrgRoleNotFound()):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, domain.ErrOrgRoleAlreadyExists):
				c.JSON(http.StatusConflict, gin.H{"error": "name_exists"})
			case errors.Is(err, service.ErrOrgRoleInvalid()):
				// THE-SILENT-DROP: a supplied blank name is a BAD REQUEST.
				// It used to be dropped and answered 200 OK, so a rename
				// that changed nothing was reported as a success.
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "message": err.Error()})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		c.JSON(http.StatusOK, toSafeOrgRole(role))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"role_id": role.ID, "organization_id": role.OrgID},
		})
	}
}

// HandleDeleteOrgRole soft-deletes (or hard-deletes per repo) a role.
func HandleDeleteOrgRole(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		actor, _ := principalForCtx(c)
		if err := deps.OrgRoleService.DeleteRoleForActor(c.Request.Context(), actor, roleID); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			// THE-SIXTEEN-ELSES: 404 only for the real miss.
			if errors.Is(err, service.ErrOrgRoleNotFound()) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": roleID})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"role_id": roleID},
		})
	}
}

// HandleAddRoleScope binds an api-resource scope to a role.
func HandleAddRoleScope(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		var req struct {
			ResourceID uuid.UUID `json:"resource_id"`
			ScopeName  string    `json:"scope_name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		actor, _ := principalForCtx(c)
		if err := deps.OrgRoleService.AddScopeForActor(c.Request.Context(), actor, roleID, req.ResourceID, req.ScopeName); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"role_id": roleID, "scope_name": req.ScopeName})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.scope_added",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"role_id":    roleID,
				"scope_name": req.ScopeName,
			},
		})
	}
}

// HandleRemoveRoleScope unbinds an api-resource scope from a role.
func HandleRemoveRoleScope(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		scopeName := c.Param("scope_name")
		actor, _ := principalForCtx(c)
		if err := deps.OrgRoleService.RemoveScopeForActor(c.Request.Context(), actor, roleID, scopeName); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			// THE-SIXTEEN-ELSES: 404 only for the real miss.
			if errors.Is(err, service.ErrOrgRoleNotFound()) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"role_id": roleID, "scope_name": scopeName})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.scope_removed",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"role_id": roleID, "scope_name": scopeName},
		})
	}
}

// HandleListRolesForUser lists every role currently bound to the :id user.
func HandleListRolesForUser(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}
		actor, _ := principalForCtx(c)
		roles, err := deps.OrgRoleService.ListRolesForUserForActor(c.Request.Context(), actor, userID)
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeOrgRole, 0, len(roles))
		for _, r := range roles {
			out = append(out, toSafeOrgRole(r))
		}
		c.JSON(http.StatusOK, gin.H{"roles": out, "count": len(out)})
	}
}

// HandleAssignRoleToUser binds role_id (from JSON body) to the :id user.
func HandleAssignRoleToUser(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}
		var req struct {
			RoleID uuid.UUID `json:"role_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		actor, _ := principalForCtx(c)
		if err := deps.OrgRoleService.AssignRoleToUserForActor(c.Request.Context(), actor, userID, req.RoleID); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "role_id": req.RoleID})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.assigned",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"user_id": userID, "role_id": req.RoleID},
		})
	}
}

// HandleRemoveRoleFromUser unbinds :role_id from the :id user.
func HandleRemoveRoleFromUser(deps RBACHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
			return
		}
		roleID, err := uuid.Parse(c.Param("role_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role id"})
			return
		}
		actor, _ := principalForCtx(c)
		if err := deps.OrgRoleService.RemoveRoleFromUserForActor(c.Request.Context(), actor, userID, roleID); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			// THE-SIXTEEN-ELSES: 404 only for the real miss.
			if errors.Is(err, service.ErrOrgRoleNotFound()) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "role_id": roleID})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org_role.unassigned",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"user_id": userID, "role_id": roleID},
		})
	}
}
