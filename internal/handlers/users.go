package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// UsersHandlerDeps wires the /api/v1/users admin group.
//
// UserService preferred; UserRepo legacy fallback (read-only).
// Audit defaults to audit.NoopService{}.
//
// Authority decision (this slice): every route requires
// RequireSiteAdmin(). Per-org `org_admin` access is deferred to a
// follow-up slice where a CE-side org-scoped authorization gate can
// enforce the Identuum policy (org_admin manages only own org).
// Mirroring the monolith's mw.RequireScopesAny() shape requires
// scope-aware bearer claims that OSS does not yet wire end-to-end.
type UsersHandlerDeps struct {
	UserService *service.UserService
	UserRepo    repository.UserRepository
	Audit       audit.Service
	// SessionRevoker is the best-effort seam consulted by the
	// admin MFA-reset handler so a target whose MFA enrolment is
	// cleared cannot keep authenticating through a pre-existing
	// session or refresh token. Defaults to
	// service.NoopSessionRevoker when nil so the rest of the
	// surface remains callable in deployments that have not yet
	// wired a session store. The seam contract is warn-and-continue
	// (errors do not fail the request); the matching pattern is
	// established by PasswordResetService.
	SessionRevoker service.SessionRevoker
	// RefreshTokenRevoker is the parallel seam for OAuth refresh
	// tokens: clearing MFA must also stop any pre-existing
	// refresh-token-bound access from minting fresh access tokens.
	// Defaults to service.NoopRefreshTokenRevoker when nil. Same
	// warn-and-continue contract as SessionRevoker.
	RefreshTokenRevoker service.UserRefreshTokenRevoker

	// PolicyOrgs resolves the TARGET organization so the admin user
	// paths (create, update, bulk) can carry the org's password
	// policy into the service call instead of silently holding every
	// admin-created user to the strict default (THE-TWO-DEBTS, debt
	// B). Nil-safe: when unwired, the service's documented safe
	// defaults apply (nil ⇒ strict complexity, 0 ⇒ floor 8).
	PolicyOrgs OrgPolicyReader

	// StartupReport receives a fatal fault if neither UserService nor
	// UserRepo is wired — instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// OrgPolicyReader is the narrow read-only seam the user handlers need
// to resolve the target org's password policy. Satisfied by
// repository.OrganizationRepository.
type OrgPolicyReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error)
}

// resolveOrgPasswordPolicy reads the target org's password policy for
// the admin user paths. Nil-safe on every input: any unreadable org
// yields (nil, 0) — the service's documented safe defaults (strict
// complexity, floor 8). The wire NEVER feeds these (BIND-OPTIONS-GATE-1
// adjudicated them never-client-settable); the min length has no
// org-level column, so 0 keeps the documented floor deliberately.
func resolveOrgPasswordPolicy(ctx context.Context, orgs OrgPolicyReader, orgID uuid.UUID) (*bool, int) {
	if orgs == nil || orgID == uuid.Nil {
		return nil, 0
	}
	org, err := orgs.GetByID(ctx, orgID)
	if err != nil || org == nil {
		return nil, 0
	}
	pce := org.PasswordComplexityEnabled
	return &pce, 0
}

// RegisterUsersRoutes mounts the user admin group onto router.
//
// Implemented (LIVE) when UserService non-nil:
//
//	GET    /api/v1/users                       (site_admin OR org_admin w/ users:read)
//	GET    /api/v1/users/:id                   (site_admin OR org_admin w/ users:read)
//	POST   /api/v1/users                       (site_admin OR org_admin w/ users:create)
//	PUT    /api/v1/users/:id                   (site_admin OR org_admin w/ users:update)
//	DELETE /api/v1/users/:id                   (site_admin)
//	POST   /api/v1/users/:id/restore           (site_admin)
//	POST   /api/v1/users/:id/recovery/reset-mfa (site_admin OR org_admin w/ users:mfa:revoke)
//
// Authority decisions (this slice):
//
//   - Read + Create + Update routes flip to the composed
//     site_admin-OR-org_admin-with-scope guard. The HTTP layer
//     blocks role/scope failures; the OSS UserService.*ForActor
//     methods enforce same-tenant authority at the service layer
//     (defense in depth). org_admin can never read, list, create,
//     update, or move users outside their own organization, and
//     cannot create or promote a site_admin user.
//   - DELETE and POST /:id/restore stay site_admin-only. The
//     service layer also rejects an org_admin Delete/Restore for
//     cross-org or site_admin targets, but the safer HTTP default
//     is the unchanged site_admin guard. A future slice can
//     loosen these once an audit-export gate is wired so a
//     misbehaving org_admin's deletion sweep is observable.
//   - Bulk-create is live and SYNCHRONOUS (user_bulk_create.go —
//     best-effort per-row results in one response; the ancestor's
//     async JobService design was not carried into OSS).
//     Approve-registration is live (POST /:id/approve).
//   - Reset-MFA is live for site_admin OR org_admin with the
//     users:mfa:revoke scope. The handler delegates the tenant
//     boundary to UserService.ResetMFAForActor: site_admin is
//     unrestricted; org_admin may only reset MFA on users in the
//     same organization and may NOT target a site_admin user. The
//     service then calls ResetMFA which clears mfa_enabled,
//     mfa_secret, and mfa_recovery_codes; no other field on the
//     row is touched and the response is the safe user projection
//     (never includes mfa_secret or codes).
func RegisterUsersRoutes(router gin.IRouter, deps UsersHandlerDeps) {
	if deps.UserService == nil && deps.UserRepo == nil {
		// P-018: a user-identity admin surface with no service or repo
		// cannot answer any request. FATAL (identity is security-critical).
		// Record the fault and mount a uniform service-missing fallback for
		// the whole group instead of panicking.
		deps.StartupReport.Fatal(
			"users-routes",
			"user admin surface unavailable: neither UserService nor UserRepo is wired",
		)
		g := router.Group("/api/v1/users")
		g.GET("", serviceMissingFallback("users"))
		g.GET("/:id", serviceMissingFallback("users"))
		g.POST("", serviceMissingFallback("users"))
		g.PUT("/:id", serviceMissingFallback("users"))
		g.DELETE("/:id", serviceMissingFallback("users"))
		g.POST("/:id/restore", serviceMissingFallback("users"))
		g.POST("/:id/recovery/reset-mfa", serviceMissingFallback("users"))
		g.POST("/bulk", serviceMissingFallback("users"))
		g.POST("/:id/approve", serviceMissingFallback("users"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.SessionRevoker == nil {
		deps.SessionRevoker = service.NoopSessionRevoker{}
	}
	if deps.RefreshTokenRevoker == nil {
		deps.RefreshTokenRevoker = service.NoopRefreshTokenRevoker{}
	}

	g := router.Group("/api/v1/users")

	// Read paths: site_admin OR org_admin with users:read.
	read := g.Group("")
	read.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersRead))

	// docgen:endpoint
	// docgen:surface=users
	// docgen:method=GET
	// docgen:path=/api/v1/users
	// docgen:summary=List users (paginated via page + page_size query params; safe projection — never exposes password_hash or recovery codes).
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:response=oss.handlers.safeUser
	// docgen:notes=org_admin actor additionally requires the users:read scope; site_admin sees every user; org_admin sees own-org users only (handler enforces).
	read.GET("", HandleListUsers(deps))

	// docgen:endpoint
	// docgen:surface=users
	// docgen:method=GET
	// docgen:path=/api/v1/users/:id
	// docgen:summary=Show a single user by id (safe projection — never exposes password_hash or recovery codes).
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:response=oss.handlers.safeUser
	// docgen:notes=org_admin actor additionally requires the users:read scope; cross-org reads denied at the handler layer.
	read.GET("/:id", HandleGetUser(deps))

	if deps.UserService != nil {
		// Create: site_admin OR org_admin with users:create.
		create := g.Group("")
		create.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersCreate))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=POST
		// docgen:path=/api/v1/users
		// docgen:summary=Create a user (password hashed before persistence; password and password_hash never appear in the response body or audit metadata).
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:response=oss.handlers.safeUser
		// docgen:notes=org_admin actor additionally requires the users:create scope.
		// docgen:status=201
		create.POST("", HandleCreateUser(deps))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=POST
		// docgen:path=/api/v1/users/bulk
		// docgen:summary=Bulk-create up to 50 users in one org (synchronous, best-effort; returns per-item created + failed results). Reuses the single-create path per user (same validation, org-scoping, secure defaults, UUIDv7).
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:notes=org_admin actor additionally requires the users:create scope and may only bulk-create into their own org. A batch that is empty or exceeds 50 returns 400 with nothing created. Per-user failures do not abort the batch and succeeded users are not rolled back.
		create.POST("/bulk", HandleBulkCreateUsers(deps))

		// Update: site_admin OR org_admin with users:update.
		update := g.Group("")
		update.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersUpdate))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=PUT
		// docgen:path=/api/v1/users/:id
		// docgen:summary=Update a user.
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:response=oss.handlers.safeUser
		// docgen:notes=org_admin actor additionally requires the users:update scope.
		update.PUT("/:id", HandleUpdateUser(deps))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=POST
		// docgen:path=/api/v1/users/:id/approve
		// docgen:summary=Approve a pending self-registered user (clears the public_registration hold so the user can authenticate).
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:response=oss.handlers.safeUser
		// docgen:notes=Only a user in the pending state (banned=true, role=org_user) may be approved; already-active users, admins, and missing users return 4xx (409/403/404). org_admin additionally requires the users:update scope and may only approve users in their own organization.
		update.POST("/:id/approve", HandleApproveUser(deps))

		// Delete: site_admin OR org_admin with users:delete (USERS-DELETE-GUARD-1,
		// THE-GUARDED-DELETE). AdminPermissionsModel.md: site_admin "cannot manage
		// the resources (such as users)" belonging to tenant orgs, while org_admin
		// holds "day-to-day control of that organization's resources (users, ...)".
		// The previous RequireSiteAdmin route both blocked the actor the model
		// empowers AND made DeleteUserForActor's org_admin same-org branch
		// unreachable dead code. The service already enforces same-org scope and
		// the site_admin-protection invariant, so the guard now matches update.
		del := g.Group("")
		del.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersDelete))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=DELETE
		// docgen:path=/api/v1/users/:id
		// docgen:summary=Soft-delete a user.
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:notes=site_admin can delete any ordinary user (the model's lost-all-org_admins recovery clause depends on it). org_admin additionally requires the users:delete scope and may only delete users in their own organization; cross-org and site_admin targets get the anti-enumeration 404.
		del.DELETE("/:id", HandleDeleteUser(deps))

		// Restore remains site_admin-only at the HTTP layer (infrastructure
		// recovery, not day-to-day tenant management).
		siteOnly := g.Group("")
		siteOnly.Use(mw.RequireSiteAdmin())

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=POST
		// docgen:path=/api/v1/users/:id/restore
		// docgen:summary=Restore a previously soft-deleted user.
		// docgen:tier=oss
		// docgen:auth=site_admin
		// docgen:response=oss.handlers.safeUser
		siteOnly.POST("/:id/restore", HandleRestoreUser(deps))

		// Reset-MFA: site_admin OR org_admin with users:mfa:revoke.
		// Authority decision is delegated to UserService.ResetMFAForActor
		// at the service layer so the cross-org / site_admin-target
		// guards mirror the existing UpdateUserForActor matrix.
		mfaReset := g.Group("")
		mfaReset.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeUsersMFARevoke))

		// docgen:endpoint
		// docgen:surface=users
		// docgen:method=POST
		// docgen:path=/api/v1/users/:id/recovery/reset-mfa
		// docgen:summary=Reset a user's MFA (clears mfa_enabled, mfa_secret, and mfa_recovery_codes; idempotent).
		// docgen:tier=oss
		// docgen:auth=site_admin|org_admin
		// docgen:response=oss.handlers.safeUser
		// docgen:notes=site_admin can reset MFA for any target. org_admin additionally requires the users:mfa:revoke scope and may only reset MFA for users in the org_admin's own organization (cross-org and site_admin targets get 403). The response is the safe user projection — it never includes mfa_secret or mfa_recovery_codes. Resetting a user without MFA enrolled still returns 200.
		mfaReset.POST("/:id/recovery/reset-mfa", HandleResetUserMFA(deps))
	} else {
		// Read-only deployments: every mutation 501s; the scaffold
		// stub group still mounts behind RequireSiteAdmin so
		// non-site-admin actors get 403 before hitting the stub.
		stub := g.Group("")
		stub.Use(mw.RequireSiteAdmin())
		stub.POST("", userServiceMissing("create"))
		stub.PUT("/:id", userServiceMissing("update"))
		stub.DELETE("/:id", userServiceMissing("delete"))
		stub.POST("/:id/restore", userServiceMissing("restore"))
		stub.POST("/:id/recovery/reset-mfa", userServiceMissing("reset MFA"))
		stub.POST("/:id/approve", userServiceMissing("approve registration"))
		stub.POST("/bulk", userServiceMissing("bulk-create"))
	}

}

// RegisterProfileRoute mounts GET /api/v1/profile. Authentication is
// required (any role), and the response is the safe projection of
// the principal's own user row. The route is registered
// independently of RegisterUsersRoutes so a deployment that wires
// only the user-read repository (no service) can still expose
// /profile.
//
// Behavior:
//
//   - no principal              → 401
//   - principal w/ no UserID    → 401 (defence: an upstream populator
//     that planted a roleless principal
//     is treated as not authenticated)
//   - user row missing          → 404
//   - found                     → 200 + safeUser
func RegisterProfileRoute(router gin.IRouter, deps UsersHandlerDeps) {
	if deps.UserService == nil && deps.UserRepo == nil {
		// P-018: the self-profile surface needs a user source. FATAL
		// (identity). Record the fault + mount the fallback, no panic.
		deps.StartupReport.Fatal(
			"profile-route",
			"profile surface unavailable: neither UserService nor UserRepo is wired",
		)
		g := router.Group("/api/v1/profile")
		g.GET("", serviceMissingFallback("profile"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	g := router.Group("/api/v1/profile")
	g.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=profile
	// docgen:method=GET
	// docgen:path=/api/v1/profile
	// docgen:summary=Get the authenticated principal's own user profile (safe projection — never exposes password_hash or recovery codes).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:response=oss.handlers.safeUser
	// docgen:notes=Returns 401 when no principal is present or when the principal has no UserID; 404 when the user row is missing.
	g.GET("", HandleGetProfile(deps))
}

// HandleGetProfile returns the authenticated principal's own user
// row. The response shape mirrors safeUser; no MFA/password/token
// material crosses the wire.
func HandleGetProfile(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok || p.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var (
			u   *domain.User
			err error
		)
		if deps.UserService != nil {
			u, err = deps.UserService.GetByID(c.Request.Context(), p.UserID)
		} else {
			u, err = deps.UserRepo.GetByID(c.Request.Context(), p.UserID)
		}
		if err != nil || u == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeUser(u))
	}
}

// safeUser is the on-the-wire user shape. Sensitive fields
// (PasswordHash, ActivationTokenHash, VerificationTokenHash,
// MFASecret, MFARecoveryCodes) are deliberately omitted.
type safeUser struct {
	ID                     uuid.UUID       `json:"id"`
	OrganizationID         uuid.UUID       `json:"organization_id"`
	Email                  string          `json:"email"`
	Name                   *string         `json:"name,omitempty"`
	Role                   domain.UserRole `json:"role"`
	AuthSource             string          `json:"auth_source"`
	EmailVerified          bool            `json:"email_verified"`
	MFAEnabled             bool            `json:"mfa_enabled"`
	MFAPolicy              *string         `json:"mfa_policy,omitempty"`
	Banned                 bool            `json:"banned"`
	OIDCLinked             bool            `json:"oidc_linked"`
	RequiresPasswordChange bool            `json:"requires_password_change"`
	OrganizationName       *string         `json:"organization_name,omitempty"`
	Domain                 *string         `json:"domain,omitempty"`
	ExternalID             *string         `json:"external_id,omitempty"`
	LastLoginAt            *time.Time      `json:"last_login_at,omitempty"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
	DeletedAt              *time.Time      `json:"deleted_at,omitempty"`
}

func toSafeUser(u *domain.User) safeUser {
	if u == nil {
		return safeUser{}
	}
	return safeUser{
		ID:                     u.ID,
		OrganizationID:         u.OrganizationID,
		Email:                  u.Email,
		Name:                   u.Name,
		Role:                   u.Role,
		AuthSource:             u.AuthSource,
		EmailVerified:          u.EmailVerified,
		MFAEnabled:             u.MFAEnabled,
		MFAPolicy:              u.MFAPolicy,
		Banned:                 u.Banned,
		OIDCLinked:             u.OIDCLinked,
		RequiresPasswordChange: u.RequiresPasswordChange,
		OrganizationName:       u.OrganizationName,
		Domain:                 u.Domain,
		ExternalID:             u.ExternalID,
		LastLoginAt:            u.LastLoginAt,
		CreatedAt:              u.CreatedAt,
		UpdatedAt:              u.UpdatedAt,
		DeletedAt:              u.DeletedAt,
	}
}

// HandleListUsers returns paginated users in safe-projection form.
// site_admin sees rows across tenants; org_admin sees own-org only.
// The tenant scope is enforced at the service layer via
// UserService.ListUsersForActor.
func HandleListUsers(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		pageSize := parsePositiveQuery(c, "page_size", 50, 200)
		page := parsePositiveQuery(c, "page", 1, 1<<16)
		opts := repository.ListUserOptions{
			Pagination: repository.NewPagination(page, pageSize),
			Sort:       repository.NewUserSort("created_at", true),
		}
		actor, _ := mw.PrincipalFromContext(c)
		var (
			users []*domain.User
			total int
			err   error
		)
		if deps.UserService != nil {
			users, total, err = deps.UserService.ListUsersForActor(c.Request.Context(), actor, opts)
		} else {
			// Read-only deployment: only site_admin can reach the
			// read path (guard mounted), so cross-tenant List is
			// the correct shape.
			users, total, err = deps.UserRepo.List(c.Request.Context(), opts)
		}
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		out := make([]safeUser, 0, len(users))
		for _, u := range users {
			out = append(out, toSafeUser(u))
		}
		c.JSON(http.StatusOK, gin.H{
			"users":     out,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
	}
}

// HandleGetUser returns a single user by id in safe-projection form.
// org_admin actors cannot see users outside their own org or any
// site_admin user; those cases return 403.
func HandleGetUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		var u *domain.User
		if deps.UserService != nil {
			u, err = deps.UserService.GetUserForActor(c.Request.Context(), actor, id)
		} else {
			u, err = deps.UserRepo.GetByID(c.Request.Context(), id)
		}
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil || u == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeUser(u))
	}
}

// HandleCreateUser creates a user. Body fields: email, password,
// name, role, organization_id. Plaintext password is hashed by the
// service; only the hash is persisted.
//
// Authority: site_admin must specify organization_id; org_admin's
// target organization_id is forced to actor.OrganizationID by the
// service layer. org_admin cannot create site_admin.
func HandleCreateUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			OrganizationID uuid.UUID       `json:"organization_id"`
			Email          string          `json:"email"`
			Password       string          `json:"password"`
			Name           string          `json:"name,omitempty"`
			Role           domain.UserRole `json:"role"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		// Target org for the password policy: the requested org, or the
		// actor's own org when omitted (the org_admin self-org case the
		// service substitutes anyway).
		policyOrgID := req.OrganizationID
		if policyOrgID == uuid.Nil && actor != nil {
			policyOrgID = actor.OrganizationID
		}
		pce, minLen := resolveOrgPasswordPolicy(c.Request.Context(), deps.PolicyOrgs, policyOrgID)
		created, err := deps.UserService.CreateUserForActor(c.Request.Context(), actor, service.CreateUserOptions{
			OrganizationID:            req.OrganizationID,
			Email:                     req.Email,
			Password:                  req.Password,
			Name:                      req.Name,
			Role:                      req.Role,
			PasswordComplexityEnabled: pce,
			MinPasswordLength:         minLen,
		})
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, toSafeUser(created))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"user_id":         created.ID,
				"email":           created.Email,
				"role":            string(created.Role),
				"organization_id": created.OrganizationID,
			},
		})
	}
}

// HandleUpdateUser mutates a user by id. Only the listed fields are
// considered; password is hashed before persistence. org_admin
// cannot mutate site_admin users, cross-org users, or promote a
// target to site_admin — those are 403 from UpdateUserForActor.
func HandleUpdateUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Email         *string          `json:"email,omitempty"`
			Password      *string          `json:"password,omitempty"`
			Name          *string          `json:"name,omitempty"`
			Role          *domain.UserRole `json:"role,omitempty"`
			Active        *bool            `json:"active,omitempty"`
			Banned        *bool            `json:"banned,omitempty"`
			EmailVerified *bool            `json:"email_verified,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// active is the public, pre-split wire contract; banned is the
		// persistence representation. Keep accepting the OSS-native banned
		// field, but let an explicit active value take precedence when both
		// are present so established clients retain the monolith semantics.
		if req.Active != nil {
			banned := !*req.Active
			req.Banned = &banned
		}
		actor, _ := mw.PrincipalFromContext(c)
		// Password policy follows the TARGET user's org. Resolved only
		// when a password is actually changing; a failed lookup falls
		// back to the strict defaults (conservative direction).
		var pce *bool
		minLen := 0
		if req.Password != nil {
			if target, terr := deps.UserService.GetUserForActor(c.Request.Context(), actor, id); terr == nil && target != nil {
				pce, minLen = resolveOrgPasswordPolicy(c.Request.Context(), deps.PolicyOrgs, target.OrganizationID)
			}
		}
		updated, err := deps.UserService.UpdateUserForActor(c.Request.Context(), actor, id, service.UpdateUserOptions{
			Email:                     req.Email,
			Password:                  req.Password,
			Name:                      req.Name,
			Role:                      req.Role,
			Banned:                    req.Banned,
			EmailVerified:             req.EmailVerified,
			PasswordComplexityEnabled: pce,
			MinPasswordLength:         minLen,
		})
		if errors.Is(err, domain.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		// A policy-refused password answers an HONEST 400 weak_password
		// (THE-HONEST-REFUSAL) — the live matrix caught it collapsing
		// into 404 not-found. RG10 stays intact: UpdateUserForActor
		// answers not-found for any target outside the caller's
		// visibility BEFORE the password is ever validated, so this
		// branch can only fire for a target the caller may touch and
		// leaks no existence. Message text is policy prose only
		// (the change-password precedent), never credential material.
		if err != nil && domain.IsPasswordPolicyError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password", "message": err.Error()})
			return
		}
		if err != nil {
			// THE-DEFAULT-THAT-LIES: 404 is reserved for the two
			// not-found sentinels (which RG10 also rides on); a
			// duplicate email is an honest 409 (own-org admin surface —
			// the same enumeration posture bulk's vocabulary already
			// rests on); everything unknown — including the hashing
			// sentinel — is an INTERNAL fault and says so, instead of
			// masquerading as a missing user.
			switch {
			case errors.Is(err, service.ErrUserNotFound()), errors.Is(err, domain.ErrUserNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, domain.ErrUserAlreadyExists):
				c.JSON(http.StatusConflict, gin.H{"error": "email_exists"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		// Lifecycle-first cascade (P-018 best-effort): when this update
		// BANS the user, the ban has persisted above — revoke the user's
		// live sessions + refresh tokens so the Stage-1 bearer session
		// check rejects them. A revoke failure is logged at ERROR and
		// never breaks the update or panics.
		if req.Banned != nil && *req.Banned {
			cascadeRevokeUser(c.Request.Context(), deps.SessionRevoker, deps.RefreshTokenRevoker, updated.ID, "user_banned")
		}
		c.JSON(http.StatusOK, toSafeUser(updated))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user.updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"user_id": updated.ID},
		})
	}
}

// HandleDeleteUser soft-deletes a user. Site-admin-only at the
// HTTP layer; the service-layer guard is still consulted so a
// future loosening cannot accidentally permit cross-org deletes.
func HandleDeleteUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		if err := deps.UserService.DeleteUserForActor(c.Request.Context(), actor, id); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// Lifecycle-first cascade (P-018 best-effort): the soft-delete has
		// persisted; revoke the user's live sessions + refresh tokens so
		// the Stage-1 bearer session check rejects them on the next
		// request. A revoke failure is logged at ERROR and never breaks
		// the delete or panics.
		cascadeRevokeUser(c.Request.Context(), deps.SessionRevoker, deps.RefreshTokenRevoker, id, "user_deleted")
		c.JSON(http.StatusOK, gin.H{"deleted": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"user_id": id},
		})
	}
}

// HandleRestoreUser un-deletes a soft-deleted user.
func HandleRestoreUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		if err := deps.UserService.RestoreUserForActor(c.Request.Context(), actor, id); err != nil {
			if errors.Is(err, domain.ErrForbidden) {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"restored": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user.restored",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"user_id": id},
		})
	}
}

// HandleResetUserMFA clears the target user's MFA enrollment.
// Authority is site_admin OR org_admin with users:mfa:revoke at
// the HTTP layer; the same-organization / no-site_admin-target
// guard is enforced at the service layer via
// UserService.ResetMFAForActor (mirrors UpdateUserForActor's
// matrix). The service-layer reset call does not change password
// hash, role, organization, email, active/deleted status, or
// password-reset state. Response is the safe user projection —
// mfa_secret and mfa_recovery_codes are never on the wire.
// Idempotent: a target without MFA enrolled still returns 200.
//
// After the MFA fields are cleared, the handler fires
// deps.SessionRevoker.RevokeUserSessions for the target so any
// pre-existing cookie session or refresh token stops authenticating
// — the same warn-and-continue pattern PasswordResetService uses on
// the completion path. A revocation failure is intentionally NOT
// propagated to the caller: the MFA state has already been cleared
// at this point, the seam contract is best-effort, and surfacing a
// 500 here would leave the operator unable to tell whether the
// reset itself succeeded. No raw session/token material reaches the
// audit row.
func HandleResetUserMFA(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		updated, err := deps.UserService.ResetMFAForActor(c.Request.Context(), actor, id)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrUnauthorized):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			case errors.Is(err, domain.ErrForbidden):
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			case errors.Is(err, service.ErrUserNotFound()):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}
		_ = deps.SessionRevoker.RevokeUserSessions(c.Request.Context(), updated.ID, "mfa_reset_by_admin", map[string]any{
			"organization_id": updated.OrganizationID,
		})
		// Refresh-token revocation is best-effort: the seam returns
		// the count of newly revoked rows, which we surface in audit
		// metadata when the call succeeded. On error we drop the
		// count silently — the seam contract forbids partial-
		// success claims and we have no safe way to express "we
		// tried" in the audit row without inviting confusion.
		refreshRevoked, refreshErr := deps.RefreshTokenRevoker.RevokeAllForUser(c.Request.Context(), updated.ID)
		c.JSON(http.StatusOK, toSafeUser(updated))
		auditMeta := map[string]any{
			"user_id":         updated.ID,
			"organization_id": updated.OrganizationID,
		}
		// Actor identity (role + org + user id) is added so an
		// org_admin reset can be distinguished from a site_admin
		// reset in the audit row. Strictly identifier-shaped —
		// NEVER a token, MFA secret, recovery code, session id, or
		// refresh hash.
		if actor != nil {
			auditMeta["actor_role"] = string(actor.Role)
			if actor.UserID != uuid.Nil {
				auditMeta["actor_user_id"] = actor.UserID
			}
			if actor.OrganizationID != uuid.Nil {
				auditMeta["actor_organization_id"] = actor.OrganizationID
			}
		}
		if refreshErr == nil {
			auditMeta["refresh_tokens_revoked_count"] = refreshRevoked
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    string(domain.AuditOrgAdminMFAReset),
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  auditMeta,
		})
	}
}

func userServiceMissing(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":     "not implemented",
			"operation": op,
			"reason":    "UserService not yet relocated into the OSS module; " + op + " requires service-layer validation.",
		})
	}
}
