package handlers

import (
	"context"
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

// OrganizationsHandlerDeps wires /api/v1/organizations.
//
// OrganizationService preferred; OrganizationRepo legacy fallback
// (read-only). Audit defaults to NoopService.
//
// Authority decision (this slice): every route requires
// RequireSiteAdmin(). The Identuum admin-authority model preserves
// site_admin's right to manage infrastructure-level Active/Deleted
// status; per-org `org_admin` access is deferred until a future
// slice with a CE-side per-org gate.
type OrganizationsHandlerDeps struct {
	OrganizationService *service.OrganizationService
	OrganizationRepo    repository.OrganizationRepository
	Audit               audit.Service

	// StartupReport receives a fatal fault if neither service nor repo is
	// wired — instead of panicking (P-018). Nil-safe.
	StartupReport *lifecycle.StartupReport

	// SessionRevoker, RefreshTokenRevoker, and MemberLister wire the
	// lifecycle→revocation cascade for org deactivate/delete (R3 / R1-secondary).
	// All nil-safe: when unwired the cascade is a no-op (scaffold deployments).
	//   - SessionRevoker      → the existing org-scoped RevokeByOrganizationID.
	//   - RefreshTokenRevoker → per-member RevokeAllForUser fan-out.
	//   - MemberLister        → enumerates org members for the refresh fan-out.
	SessionRevoker      OrgSessionRevoker
	RefreshTokenRevoker service.UserRefreshTokenRevoker
	MemberLister        OrgMemberLister

	// ActivationResender re-issues + re-dispatches a pending org's
	// activation token (POST /:id/resend-activation). Nil-safe: when
	// unwired the route fails closed with 503.
	ActivationResender OrgActivationResender

	// AdminCounter projects per-org admin state (is_claimed /
	// can_assign_admin) onto the org payloads (PHANTOM-NO-ADMIN).
	// Wired from the user repository. Nil-safe in a specific, loud
	// way: when unwired the register call records a FATAL fault
	// (P-018: not-serving, never a panic) and the handlers emit the
	// admin-state fields as ABSENT — never false — so a missing
	// counter can never masquerade as "no administrator".
	AdminCounter OrgAdminCounter
}

// OrgAdminCounter is the narrow user-repository seam the organizations
// surface needs to project admin state onto org payloads. Satisfied by
// repository.UserRepository (both the pgx and cached implementations).
type OrgAdminCounter interface {
	// CountOrgAdminsByOrganizations returns, per org id, the number of
	// live org_admin rows (not deleted, not banned).
	CountOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error)
	// CountVerifiedOrgAdminsByOrganizations narrows that count to
	// email-verified rows.
	CountVerifiedOrgAdminsByOrganizations(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]int, error)
}

// RegisterOrganizationsRoutes mounts /api/v1/organizations onto router.
//
// Implemented (LIVE) when OrganizationService non-nil:
//
//	POST   /api/v1/organizations                 (site_admin)
//	GET    /api/v1/organizations                 (site_admin)
//	GET    /api/v1/organizations/current         (any authenticated principal w/ org id)
//	GET    /api/v1/organizations/:id             (site_admin OR same-org org_admin)
//	PUT    /api/v1/organizations/:id             (site_admin)
//	DELETE /api/v1/organizations/:id             (site_admin)
//	POST   /api/v1/organizations/:id/restore     (site_admin)
//	GET    /api/v1/organizations/:id/admin-recovery-candidates (site_admin)
//	GET    /api/v1/organizations/export-candidates (site_admin OR org_admin w/ orgs:read scope)
//	POST   /api/v1/organizations/:id/resend-activation (site_admin)
//
// Authority decisions:
//
//   - List, Create, Update, Delete, Restore stay site_admin-only.
//     The Identuum admin authority model leaves infrastructure-level
//     lifecycle decisions with site_admin.
//   - GET /:id permits same-org org_admin via
//     RequireSiteAdminOrSameOrgAdmin so a tenant admin can read their
//     own org card.
//   - GET /current resolves the target org from
//     Principal.OrganizationID via RequireSiteAdminOrPrincipalOrg.
//     A site_admin with no org id (the SystemActor case) currently
//     400s at the handler because /current is a self-route and the
//     handler has no target to read.
func RegisterOrganizationsRoutes(router gin.IRouter, deps OrganizationsHandlerDeps) {
	if deps.OrganizationService == nil && deps.OrganizationRepo == nil {
		// P-018: organizations are the tenant identity boundary. FATAL.
		// Record the fault + mount a service-missing fallback (same route
		// set as the live surface) instead of panicking.
		deps.StartupReport.Fatal(
			"organizations-routes",
			"organizations admin surface unavailable: neither OrganizationService nor OrganizationRepo is wired",
		)
		g := router.Group("/api/v1/organizations")
		g.GET("", serviceMissingFallback("organizations"))
		g.POST("", serviceMissingFallback("organizations"))
		g.PUT("/:id", serviceMissingFallback("organizations"))
		g.DELETE("/:id", serviceMissingFallback("organizations"))
		g.POST("/:id/restore", serviceMissingFallback("organizations"))
		g.POST("/:id/resend-activation", serviceMissingFallback("organizations"))
		g.GET("/export-candidates", serviceMissingFallback("organizations"))
		g.GET("/:id/admin-recovery-candidates", serviceMissingFallback("organizations"))
		g.GET("/current", serviceMissingFallback("organizations"))
		g.GET("/:id", serviceMissingFallback("organizations"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.AdminCounter == nil {
		// PHANTOM-NO-ADMIN: without the admin counter the org payloads
		// cannot carry admin state. Record a FATAL wiring fault (P-018:
		// degrade to not-serving, never panic). The routes below stay
		// mounted and emit is_claimed/can_assign_admin as ABSENT —
		// never a false "no administrator".
		deps.StartupReport.Fatal(
			"organizations-admin-state",
			"organizations admin-state projection unavailable: AdminCounter (user repository) is not wired",
		)
	}

	g := router.Group("/api/v1/organizations")

	// List: site_admin sees every org; org_admin gets a single-row
	// list scoped to their own org (handler enforces). Behind the
	// composed scope guard so an org_admin without orgs:read scope
	// is rejected before any DB call.
	listGroup := g.Group("")
	listGroup.Use(mw.RequireSiteAdminOrOrgAdminWithScopesAudit(deps.Audit, domain.ScopeOrgsRead))

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations
	// docgen:summary=List organizations (paginated). site_admin sees every org; org_admin gets a single-row list scoped to their own org.
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:response=oss.handlers.safeOrganization
	// docgen:notes=org_admin actor additionally requires the orgs:read scope (denied before any DB call).
	listGroup.GET("", HandleListOrganizations(deps))

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/export-candidates
	// docgen:summary=List organizations for cross-system (IDP -> AG) linking/import planning. Safe, narrow projection — NOT the Enterprise SIEM audit-export feature. site_admin sees every non-deleted org (active + inactive); org_admin gets a single-row list scoped to their own org.
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:response=oss.handlers.organizationExportCandidate
	// docgen:notes=Ported from the ancestor's HandleListOrganizationExportCandidates (RBAC-scope-gated there too, not license-gated). org_admin actor additionally requires the orgs:read scope (denied before any DB call), mirroring the sibling list route.
	listGroup.GET("/export-candidates", HandleListOrganizationExportCandidates(deps))

	// site_admin-only: lifecycle mutations + deferred 501s.
	siteOnly := g.Group("")
	siteOnly.Use(mw.RequireSiteAdmin())
	if deps.OrganizationService != nil {
		// docgen:endpoint
		// docgen:surface=organizations
		// docgen:method=POST
		// docgen:path=/api/v1/organizations
		// docgen:summary=Create an organization.
		// docgen:tier=oss
		// docgen:auth=site_admin
		// docgen:response=oss.handlers.safeOrganization
		// docgen:status=201
		siteOnly.POST("", HandleCreateOrganization(deps))

		// docgen:endpoint
		// docgen:surface=organizations
		// docgen:method=PUT
		// docgen:path=/api/v1/organizations/:id
		// docgen:summary=Update an organization (lifecycle + policy fields).
		// docgen:tier=oss
		// docgen:auth=site_admin
		// docgen:response=oss.handlers.safeOrganization
		siteOnly.PUT("/:id", HandleUpdateOrganization(deps))

		// docgen:endpoint
		// docgen:surface=organizations
		// docgen:method=DELETE
		// docgen:path=/api/v1/organizations/:id
		// docgen:summary=Soft-delete an organization.
		// docgen:tier=oss
		// docgen:auth=site_admin
		siteOnly.DELETE("/:id", HandleDeleteOrganization(deps))

		// docgen:endpoint
		// docgen:surface=organizations
		// docgen:method=POST
		// docgen:path=/api/v1/organizations/:id/restore
		// docgen:summary=Restore a previously soft-deleted organization.
		// docgen:tier=oss
		// docgen:auth=site_admin
		// docgen:response=oss.handlers.safeOrganization
		siteOnly.POST("/:id/restore", HandleRestoreOrganization(deps))
	} else {
		siteOnly.POST("", orgServiceMissing("create"))
		siteOnly.PUT("/:id", orgServiceMissing("update"))
		siteOnly.DELETE("/:id", orgServiceMissing("delete"))
		siteOnly.POST("/:id/restore", orgServiceMissing("restore"))
	}

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=POST
	// docgen:path=/api/v1/organizations/:id/resend-activation
	// docgen:summary=Re-issue and return a pending organization's activation token (site_admin operator retrieval path). Re-dispatches via email when a notifier is wired; OSS echoes the token in the response.
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:notes=Only a pending (not-yet-active) org with an org_admin may be resent; an active org returns 409, a missing org or one with no org_admin returns 404. A fresh token is minted (the old is invalidated); the raw token is echoed in the response and never logged or audited.
	siteOnly.POST("/:id/resend-activation", HandleResendActivation(deps))

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/admin-recovery-candidates
	// docgen:summary=List the org_admin accounts of a tenant org for operator-driven recovery (reset-MFA card). site_admin only.
	// docgen:tier=oss
	// docgen:auth=site_admin
	// docgen:notes=Ported from the CE reference (unlicensed, OSS-tier). Empty array when the org has no org_admin rows; System Org and unknown orgs 404.
	siteOnly.GET("/:id/admin-recovery-candidates", HandleListOrgAdminRecoveryCandidates(deps))

	// /current: site_admin OR any principal w/ org id. Mounted
	// before the /:id route to win the gin route-priority match.
	currentGroup := g.Group("")
	currentGroup.Use(mw.RequireSiteAdminOrPrincipalOrg())

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/current
	// docgen:summary=Show the authenticated principal's current organization (resolved from the principal's organization_id).
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:response=oss.handlers.safeOrganization
	// docgen:notes=Mounted before /:id so the gin route-priority match resolves /current correctly. Middleware short-circuits to site_admin OR a principal carrying an organization id.
	currentGroup.GET("/current", HandleGetCurrentOrganization(deps))

	// /:id: site_admin OR same-org org_admin.
	sameOrg := g.Group("")
	sameOrg.Use(mw.RequireSiteAdminOrSameOrgAdmin("id"))

	// docgen:endpoint
	// docgen:surface=organizations
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id
	// docgen:summary=Show a single organization by id (site_admin OR same-org org_admin).
	// docgen:tier=oss
	// docgen:auth=site_admin|org_admin
	// docgen:response=oss.handlers.safeOrganization
	// docgen:notes=org_admin actor must be a member of the requested org (handler enforces same-org binding).
	sameOrg.GET("/:id", HandleGetOrganization(deps))
}

// safeOrganization is the on-the-wire org shape. The Organization
// struct carries no secret material today; the projection exists
// for forward-compat (a future field added to the domain type that
// IS sensitive will be omitted by default rather than leaking).
type safeOrganization struct {
	ID                          uuid.UUID  `json:"id"`
	Name                        string     `json:"name"`
	Domain                      string     `json:"domain"`
	OrgSlug                     string     `json:"org_slug"`
	Active                      bool       `json:"active"`
	MaxSessionsPerUser          int        `json:"max_sessions_per_user"`
	MFAPolicy                   string     `json:"mfa_policy"`
	AuthPolicy                  string     `json:"auth_policy"`
	ApiAuthorizationPolicy      string     `json:"api_authorization_policy,omitempty"`
	AllowPublicRegistration     bool       `json:"allow_public_registration"`
	RequireRegistrationApproval bool       `json:"require_registration_approval"`
	RequireStrictReauth         bool       `json:"require_strict_reauth"`
	LocalAdminOnly              bool       `json:"local_admin_only"`
	PasswordComplexityEnabled   bool       `json:"password_complexity_enabled"`
	Tier                        string     `json:"tier"`
	CreatedAt                   time.Time  `json:"created_at"`
	UpdatedAt                   time.Time  `json:"updated_at"`
	DeletedAt                   *time.Time `json:"deleted_at,omitempty"`

	// Admin-state projection (PHANTOM-NO-ADMIN). Pointers + omitempty:
	// when the counter is unwired or errors the fields are ABSENT so the
	// UI renders "status unavailable" — a missing counter must never
	// read as a false "no administrator". Wire names match the shared
	// types.OrganizationInfo contract the UI already consumes.
	IsClaimed      *bool `json:"is_claimed,omitempty"`
	CanAssignAdmin *bool `json:"can_assign_admin,omitempty"`
}

// orgAdminState is the computed per-org admin-state projection.
type orgAdminState struct {
	hasAdmin  bool
	canAssign bool
}

// adminStateForOrgs computes the projection for the given orgs from the
// LIVE counts: hasAdmin = live org_admin rows > 0; canAssign = hasAdmin
// with zero verified rows (the recovery-delegation state — assignment
// is offered only while no verified admin blocks delegation). Returns
// nil when the counter is unwired or errors; callers then emit the
// fields as ABSENT, never false.
func adminStateForOrgs(ctx context.Context, counter OrgAdminCounter, ids []uuid.UUID) map[uuid.UUID]orgAdminState {
	if counter == nil || len(ids) == 0 {
		return nil
	}
	admins, err := counter.CountOrgAdminsByOrganizations(ctx, ids)
	if err != nil {
		return nil
	}
	verified, err := counter.CountVerifiedOrgAdminsByOrganizations(ctx, ids)
	if err != nil {
		return nil
	}
	out := make(map[uuid.UUID]orgAdminState, len(ids))
	for _, id := range ids {
		hasAdmin := admins[id] > 0
		out[id] = orgAdminState{hasAdmin: hasAdmin, canAssign: hasAdmin && verified[id] == 0}
	}
	return out
}

// withAdminState returns s with the admin-state projection applied.
func withAdminState(s safeOrganization, st orgAdminState) safeOrganization {
	hasAdmin, canAssign := st.hasAdmin, st.canAssign
	s.IsClaimed = &hasAdmin
	s.CanAssignAdmin = &canAssign
	return s
}

func toSafeOrganization(o *domain.Organization) safeOrganization {
	if o == nil {
		return safeOrganization{}
	}
	return safeOrganization{
		ID:                          o.ID,
		Name:                        o.Name,
		Domain:                      o.Domain,
		OrgSlug:                     o.OrgSlug,
		Active:                      o.Active,
		MaxSessionsPerUser:          o.MaxSessionsPerUser,
		MFAPolicy:                   o.MFAPolicy,
		AuthPolicy:                  o.AuthPolicy,
		ApiAuthorizationPolicy:      o.ApiAuthorizationPolicy,
		AllowPublicRegistration:     o.AllowPublicRegistration,
		RequireRegistrationApproval: o.RequireRegistrationApproval,
		RequireStrictReauth:         o.RequireStrictReauth,
		LocalAdminOnly:              o.LocalAdminOnly,
		PasswordComplexityEnabled:   o.PasswordComplexityEnabled,
		Tier:                        o.Tier.String(),
		CreatedAt:                   o.CreatedAt,
		UpdatedAt:                   o.UpdatedAt,
		DeletedAt:                   o.DeletedAt,
	}
}

// parseOrgStateFilter maps the lifecycle query params onto the repository
// filter. Two independent tri-state axes, mirroring the two DB columns:
//
//	?active=true|false|all    (absent = true  — the historic default)
//	?deleted=false|true|all   (absent = false — the historic default)
//
// Absent params produce the ZERO filter, so callers that send nothing get
// byte-for-byte the old behavior (active + non-deleted). An unrecognized
// value returns ok=false — the caller answers 400 rather than silently
// serving the default for a filter the client did not ask for.
func parseOrgStateFilter(c *gin.Context) (repository.OrganizationFilter, bool) {
	var f repository.OrganizationFilter
	t, fa := true, false
	switch c.Query("active") {
	case "", "true":
		if c.Query("active") == "true" {
			f.Active = &t
		}
	case "false":
		f.Active = &fa
	case "all":
		f.IncludeInactive = true
	default:
		return f, false
	}
	switch c.Query("deleted") {
	case "", "false":
		if c.Query("deleted") == "false" {
			f.Deleted = &fa
		}
	case "true":
		f.Deleted = &t
	case "all":
		f.IncludeDeleted = true
	default:
		return f, false
	}
	return f, true
}

// HandleListOrganizations lists organizations with paging.
// site_admin sees every row; org_admin sees a single-row response
// scoped to actor.OrganizationID (their own org). org_admin with no
// org id 403s — the composed guard would already have rejected
// them at the HTTP layer, but the handler also fails closed.
func HandleListOrganizations(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		pageSize := parsePositiveQuery(c, "page_size", 50, 200)
		page := parsePositiveQuery(c, "page", 1, 1<<16)
		pagination := repository.NewPagination(page, pageSize)
		sort := repository.NewOrganizationSort("created_at", true)
		actor, _ := mw.PrincipalFromContext(c)
		// org_admin path: return only own org as a single-row list.
		if actor != nil && actor.IsOrgAdminOnly() {
			if actor.OrganizationID == uuid.Nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
				return
			}
			var (
				o   *domain.Organization
				err error
			)
			if deps.OrganizationService != nil {
				o, err = deps.OrganizationService.GetByID(c.Request.Context(), actor.OrganizationID)
			} else {
				o, err = deps.OrganizationRepo.GetByID(c.Request.Context(), actor.OrganizationID)
			}
			if err != nil || o == nil {
				c.JSON(http.StatusOK, gin.H{
					"organizations": []safeOrganization{},
					"total":         0,
					"page":          page,
					"page_size":     pageSize,
				})
				return
			}
			row := toSafeOrganization(o)
			if st, ok := adminStateForOrgs(c.Request.Context(), deps.AdminCounter, []uuid.UUID{o.ID})[o.ID]; ok {
				row = withAdminState(row, st)
			}
			c.JSON(http.StatusOK, gin.H{
				"organizations": []safeOrganization{row},
				"total":         1,
				"page":          page,
				"page_size":     pageSize,
			})
			return
		}
		// site_admin / fallback: cross-tenant list. The lifecycle filter is
		// a site_admin affordance parsed ONLY on this path — the org_admin
		// branch above returns before it and ignores the params entirely.
		filter, ok := parseOrgStateFilter(c)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filter"})
			return
		}
		var (
			orgs  []*domain.Organization
			total int
			err   error
		)
		if deps.OrganizationService != nil {
			orgs, total, err = deps.OrganizationService.List(c.Request.Context(), filter, pagination, sort)
		} else {
			orgs, total, err = deps.OrganizationRepo.List(c.Request.Context(), filter, pagination, sort)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		ids := make([]uuid.UUID, 0, len(orgs))
		for _, o := range orgs {
			ids = append(ids, o.ID)
		}
		states := adminStateForOrgs(c.Request.Context(), deps.AdminCounter, ids)
		out := make([]safeOrganization, 0, len(orgs))
		for _, o := range orgs {
			row := toSafeOrganization(o)
			if st, ok := states[o.ID]; ok {
				row = withAdminState(row, st)
			}
			out = append(out, row)
		}
		c.JSON(http.StatusOK, gin.H{
			"organizations": out,
			"total":         total,
			"page":          page,
			"page_size":     pageSize,
		})
	}
}

// HandleGetCurrentOrganization returns the organization the
// authenticated principal belongs to. The target org id comes from
// Principal.OrganizationID; site_admins without an org id (the
// SystemActor case) get 400 because /current is a self-route.
func HandleGetCurrentOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := mw.PrincipalFromContext(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if p.OrganizationID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
			return
		}
		var (
			o   *domain.Organization
			err error
		)
		if deps.OrganizationService != nil {
			o, err = deps.OrganizationService.GetByID(c.Request.Context(), p.OrganizationID)
		} else {
			o, err = deps.OrganizationRepo.GetByID(c.Request.Context(), p.OrganizationID)
		}
		if err != nil || o == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, toSafeOrganization(o))
	}
}

// HandleGetOrganization returns a single organization by id.
func HandleGetOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		// Active-agnostic read: a DEACTIVATED org must stay reachable here
		// or deactivation is a trap door (nothing to inspect, nothing to
		// re-activate from). Soft-DELETED orgs keep answering 404 — that is
		// ORG-RESTORE-1's pinned contract; /restore is their recovery door.
		var o *domain.Organization
		if deps.OrganizationService != nil {
			o, err = deps.OrganizationService.GetByIDAdminView(c.Request.Context(), id)
		} else if ar, okAdmin := deps.OrganizationRepo.(repository.AdminOrganizationRepository); okAdmin {
			o, err = ar.GetByIDAdmin(c.Request.Context(), id)
		} else {
			o, err = deps.OrganizationRepo.GetByID(c.Request.Context(), id)
		}
		if err != nil || o == nil || o.DeletedAt != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		row := toSafeOrganization(o)
		if st, ok := adminStateForOrgs(c.Request.Context(), deps.AdminCounter, []uuid.UUID{o.ID})[o.ID]; ok {
			row = withAdminState(row, st)
		}
		c.JSON(http.StatusOK, row)
	}
}

// HandleCreateOrganization creates an organization.
func HandleCreateOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name               string `json:"name"`
			Domain             string `json:"domain"`
			MaxSessionsPerUser int    `json:"max_sessions_per_user,omitempty"`
			MFAPolicy          string `json:"mfa_policy,omitempty"`
			AuthPolicy         string `json:"auth_policy,omitempty"`
			Active             bool   `json:"active,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		created, err := deps.OrganizationService.Create(c.Request.Context(), service.CreateOrganizationOptions{
			Name:               req.Name,
			Domain:             req.Domain,
			MaxSessionsPerUser: req.MaxSessionsPerUser,
			MFAPolicy:          req.MFAPolicy,
			AuthPolicy:         req.AuthPolicy,
			Active:             req.Active,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		c.JSON(http.StatusCreated, toSafeOrganization(created))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization.created",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": created.ID, "name": created.Name, "domain": created.Domain},
		})
	}
}

// HandleUpdateOrganization mutates an organization.
func HandleUpdateOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		var req struct {
			Name                        *string `json:"name,omitempty"`
			Domain                      *string `json:"domain,omitempty"`
			Active                      *bool   `json:"active,omitempty"`
			MaxSessionsPerUser          *int    `json:"max_sessions_per_user,omitempty"`
			PasswordComplexityEnabled   *bool   `json:"password_complexity_enabled,omitempty"`
			MFAPolicy                   *string `json:"mfa_policy,omitempty"`
			AuthPolicy                  *string `json:"auth_policy,omitempty"`
			ApiAuthorizationPolicy      *string `json:"api_authorization_policy,omitempty"`
			AllowPublicRegistration     *bool   `json:"allow_public_registration,omitempty"`
			RequireRegistrationApproval *bool   `json:"require_registration_approval,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		updated, err := deps.OrganizationService.Update(c.Request.Context(), id, repository.UpdateOrganizationOptions{
			Name:                        req.Name,
			Domain:                      req.Domain,
			Active:                      req.Active,
			MaxSessionsPerUser:          req.MaxSessionsPerUser,
			PasswordComplexityEnabled:   req.PasswordComplexityEnabled,
			MFAPolicy:                   req.MFAPolicy,
			AuthPolicy:                  req.AuthPolicy,
			ApiAuthorizationPolicy:      req.ApiAuthorizationPolicy,
			AllowPublicRegistration:     req.AllowPublicRegistration,
			RequireRegistrationApproval: req.RequireRegistrationApproval,
		})
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// Lifecycle-first cascade (P-018 best-effort): when this update
		// DEACTIVATES the org (active→false), the change persisted above —
		// revoke all member sessions + refresh tokens so the Stage-1
		// bearer check rejects them. A revoke failure is logged at ERROR
		// and never breaks the update.
		if req.Active != nil && !*req.Active {
			cascadeRevokeOrg(c.Request.Context(), deps.SessionRevoker, deps.RefreshTokenRevoker, deps.MemberLister, updated.ID, "org_suspended")
		}
		c.JSON(http.StatusOK, toSafeOrganization(updated))
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization.updated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": updated.ID},
		})
	}
}

// HandleDeleteOrganization soft-deletes an organization.
func HandleDeleteOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := deps.OrganizationService.Delete(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// Lifecycle-first cascade (P-018 best-effort): the org soft-delete
		// persisted; revoke all member sessions (RevokeByOrganizationID)
		// + refresh tokens so the Stage-1 bearer check rejects them. A
		// revoke failure is logged at ERROR and never breaks the delete.
		cascadeRevokeOrg(c.Request.Context(), deps.SessionRevoker, deps.RefreshTokenRevoker, deps.MemberLister, id, "org_deleted")
		c.JSON(http.StatusOK, gin.H{"deleted": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization.deleted",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": id},
		})
	}
}

// HandleRestoreOrganization un-deletes a soft-deleted organization.
func HandleRestoreOrganization(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if err := deps.OrganizationService.Restore(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"restored": id})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization.restored",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  map[string]any{"organization_id": id},
		})
	}
}

func orgServiceMissing(op string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":     "not implemented",
			"operation": op,
			"reason":    "OrganizationService not yet relocated into the OSS module; " + op + " requires service-layer validation.",
		})
	}
}
