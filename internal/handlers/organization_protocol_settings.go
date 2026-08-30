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

// OrganizationProtocolSettingsHandlerDeps wires the
// site_admin-only admin surface that reads and writes the
// per-organization DCR + SCIM enable/disable flags backed by
// the organization_protocol_settings table.
//
// OrganizationProtocolSettingsService is REQUIRED — the routes
// have nothing to back them without it.
// OrganizationService is REQUIRED for org existence validation
// (a PUT against an unknown / deleted org returns 404 instead
// of silently writing an orphan settings row that the cascade
// would never reach if the underlying org never existed).
// Audit defaults to audit.NoopService{}.
//
// Authority decision (this slice): site_admin OR same-org
// org_admin with the appropriate per-verb scope. Concretely:
//
//   - GET requires either site_admin (cross-tenant read) OR
//     same-org org_admin with `orgs:read` scope.
//   - PUT requires either site_admin (cross-tenant write) OR
//     same-org org_admin with `orgs:settings:update` scope.
//
// Cross-org probes by an org_admin (path :id ≠
// actor.OrganizationID) are rejected with 403 by the shared
// `RequireSiteAdminOrSameOrgAdminWithScopesAudit` middleware
// BEFORE the handler sees the request — matches the
// established Identuum convention for org-scoped admin routes
// (see RBAC + service-account admin surfaces). No SCIM-style
// 404 collapse here: the cross-org 403 is the project-wide
// convention for "you are not authorized for this org".
type OrganizationProtocolSettingsHandlerDeps struct {
	ProtocolSettingsService *service.OrganizationProtocolSettingsService
	OrganizationService     *service.OrganizationService
	Audit                   audit.Service

	// StartupReport threads the P-018 NOT-SERVING fault accumulator into
	// the org-scoped authz guard factory. Nil-safe.
	StartupReport *lifecycle.StartupReport
}

// RegisterOrganizationProtocolSettingsRoutes mounts the admin
// surface for per-org DCR + SCIM toggles.
//
// Routes:
//
//	GET /api/v1/organizations/:id/protocol-settings   (site_admin)
//	PUT /api/v1/organizations/:id/protocol-settings   (site_admin)
//
// Panics if required deps are missing — wiring this surface
// without backing services is a bootstrap bug.
func RegisterOrganizationProtocolSettingsRoutes(router gin.IRouter, deps OrganizationProtocolSettingsHandlerDeps) {
	if deps.ProtocolSettingsService == nil || deps.OrganizationService == nil {
		// P-018: per-org DCR/SCIM protocol-settings govern which
		// protocols a tenant exposes — security-relevant. FATAL. Record
		// the fault (naming the missing dependency) and mount a uniform
		// service-missing fallback instead of panicking.
		missing := "ProtocolSettingsService"
		if deps.ProtocolSettingsService != nil {
			missing = "OrganizationService"
		}
		deps.StartupReport.Fatal(
			"organization-protocol-settings-routes",
			"per-org protocol-settings surface unavailable: "+missing+" not wired",
		)
		g := router.Group("/api/v1/organizations/:id/protocol-settings")
		g.GET("", serviceMissingFallback("organization-protocol-settings"))
		g.PUT("", serviceMissingFallback("organization-protocol-settings"))
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/organizations/:id/protocol-settings")
	// THE-REMAINING-FOUR (2026-08-30): protocol-settings are a tenant's own
	// resource — site_admin is refused for the whole family (the underlying
	// scope guard admits it, unchanged for its org-lifecycle neighbours).
	g.Use(refuseSiteAdminOnTenantResource())

	// GET: same-org org_admin with orgs:read.
	readGroup := g.Group("")
	readGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeOrgsRead))

	// docgen:endpoint
	// docgen:surface=organization-protocol-settings
	// docgen:method=GET
	// docgen:path=/api/v1/organizations/:id/protocol-settings
	// docgen:summary=Read the per-organization DCR + SCIM enable/disable settings (source field = explicit when a row exists, default when the system fallback applies).
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.organizationProtocolSettingsResponse
	// docgen:notes=site_admin sees any active org; org_admin requires the orgs:read scope AND must be reading its OWN organization (cross-org probes return 403 via the shared scope middleware, NOT 404 — matches the existing org-scoped admin route convention). Absent row resolves to {dcr=false, scim=false}.
	readGroup.GET("", HandleGetOrganizationProtocolSettings(deps))

	// PUT: site_admin OR same-org org_admin with orgs:settings:update.
	writeGroup := g.Group("")
	writeGroup.Use(mw.RequireSiteAdminOrSameOrgAdminWithScopesAudit(deps.StartupReport, deps.Audit, "id", domain.ScopeOrgsSettingsUpdate))

	// docgen:endpoint
	// docgen:surface=organization-protocol-settings
	// docgen:method=PUT
	// docgen:path=/api/v1/organizations/:id/protocol-settings
	// docgen:summary=Upsert the per-organization DCR + SCIM enable/disable settings. Both booleans are required.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.handlers.organizationProtocolSettingsResponse
	// docgen:notes=site_admin can write any active org; org_admin requires the orgs:settings:update scope AND must be writing its OWN organization (cross-org rejected 403 with no DB write). Emits org.protocol_settings_changed audit event with target_organization_id + actor_organization_id + actor_kind + actor_role + old/new booleans; never includes secrets, tokens, IATs, or RATs.
	writeGroup.PUT("", HandlePutOrganizationProtocolSettings(deps))
}

// organizationProtocolSettingsResponse is the safe wire
// projection. The `source` field is the operator-facing hint
// distinguishing an explicit row from the system default
// fallback.
type organizationProtocolSettingsResponse struct {
	OrganizationID                   uuid.UUID `json:"organization_id"`
	DynamicClientRegistrationEnabled bool      `json:"dynamic_client_registration_enabled"`
	SCIMEnabled                      bool      `json:"scim_enabled"`
	// Source is one of "explicit" (a row exists for this org)
	// or "default" (no row; system fallback). Operators reading
	// the response can tell whether the displayed values came
	// from a recorded admin decision or are the implicit
	// default.
	Source    string     `json:"source"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// organizationProtocolSettingsPutRequest is the wire shape
// for PUT. Both booleans are REQUIRED — partial updates are
// not supported (the storage is small enough that a full
// upsert is the simplest semantic).
type organizationProtocolSettingsPutRequest struct {
	DynamicClientRegistrationEnabled *bool `json:"dynamic_client_registration_enabled"`
	SCIMEnabled                      *bool `json:"scim_enabled"`
}

// HandleGetOrganizationProtocolSettings returns the effective
// per-org settings. An absent row resolves to the system
// default ({false, false}); the `source` field exposes that
// distinction to the operator.
func HandleGetOrganizationProtocolSettings(deps OrganizationProtocolSettingsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		// Existence + active check: a PUT/GET against a deleted
		// org returns 404 in the existing org admin convention.
		// We do the same here so a probing caller cannot
		// distinguish "row missing" from "deleted org".
		if !organizationVisibleToAdmin(c, deps.OrganizationService, id) {
			return // response already written
		}
		row, source, err := readEffectiveSettings(c, deps.ProtocolSettingsService, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, toProtocolSettingsResponse(id, row, source))
	}
}

// HandlePutOrganizationProtocolSettings upserts both booleans
// for the target org. Emits org.protocol_settings_changed
// audit event with safe metadata only.
func HandlePutOrganizationProtocolSettings(deps OrganizationProtocolSettingsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if !organizationVisibleToAdmin(c, deps.OrganizationService, id) {
			return
		}
		var req organizationProtocolSettingsPutRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if req.DynamicClientRegistrationEnabled == nil || req.SCIMEnabled == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "both dynamic_client_registration_enabled and scim_enabled are required",
			})
			return
		}
		// Read the prior effective state BEFORE the upsert so
		// the audit event carries an accurate before/after
		// delta even on a brand-new row.
		before, _, err := readEffectiveSettings(c, deps.ProtocolSettingsService, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		row, err := deps.ProtocolSettingsService.SetForOrg(c.Request.Context(), id, *req.DynamicClientRegistrationEnabled, *req.SCIMEnabled)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, toProtocolSettingsResponse(id, svcSettings{
			DCREnabled:  row.DCREnabled,
			SCIMEnabled: row.SCIMEnabled,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		}, "explicit"))
		// Resolve actor metadata BEFORE emitting audit so a
		// site_admin acting on org X is distinguishable from an
		// org_admin X acting on org X. target_organization_id
		// names the row that was mutated; actor_organization_id
		// names the actor's own org binding (empty for site_admin
		// principals without an OrganizationID); actor_kind is the
		// fixed-vocabulary tag the audit consumer can filter on.
		actorKind, actorOrgID := protocolSettingsActorContext(c)
		auditMeta := map[string]any{
			"target_organization_id": id.String(),
			"actor_kind":             actorKind,
			"actor_role":             actorRoleString(c),
			"old_dynamic_client_registration_enabled": before.DCREnabled,
			"old_scim_enabled":                        before.SCIMEnabled,
			"new_dynamic_client_registration_enabled": row.DCREnabled,
			"new_scim_enabled":                        row.SCIMEnabled,
		}
		if actorOrgID != "" {
			auditMeta["actor_organization_id"] = actorOrgID
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "org.protocol_settings_changed",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  auditMeta,
		})
	}
}

// protocolSettingsActorContext resolves the actor's kind +
// actor-side organization id for the audit payload. Kind is one
// of "site_admin" | "org_admin" | "" (empty when no principal
// is on the context — should not happen behind the auth gates
// in this handler but the helper stays defensive).
func protocolSettingsActorContext(c *gin.Context) (kind, actorOrgID string) {
	p, ok := mw.PrincipalFromContext(c)
	if !ok {
		return "", ""
	}
	switch {
	case p.IsSiteAdmin():
		kind = "site_admin"
	case p.IsOrgAdminOnly():
		kind = "org_admin"
	default:
		kind = ""
	}
	if p.OrganizationID != uuid.Nil {
		actorOrgID = p.OrganizationID.String()
	}
	return kind, actorOrgID
}

// readEffectiveSettings calls service.GetEffective and
// additionally reports whether the underlying row exists. The
// distinction is consumed by the wire-shape `source` field and
// by the before/after audit metadata.
func readEffectiveSettings(c *gin.Context, svc *service.OrganizationProtocolSettingsService, id uuid.UUID) (eff svcSettings, source string, err error) {
	row, err := svc.GetEffective(c.Request.Context(), id)
	if err != nil {
		return svcSettings{}, "", err
	}
	// `source` is "explicit" iff CreatedAt is non-zero (the
	// repository populates timestamps only on real rows; the
	// system-default fallback returns a zero-value timestamp).
	src := "default"
	if !row.CreatedAt.IsZero() {
		src = "explicit"
	}
	return svcSettings{
		DCREnabled:  row.DCREnabled,
		SCIMEnabled: row.SCIMEnabled,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, src, nil
}

// svcSettings is the narrow tuple the handler keeps in hand
// for before/after audit + wire projection. Avoids leaking
// the full domain type into the handler's signatures.
type svcSettings struct {
	DCREnabled  bool
	SCIMEnabled bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// toProtocolSettingsResponse projects the settings tuple onto
// the wire response. Source is the caller-supplied hint.
func toProtocolSettingsResponse(orgID uuid.UUID, s svcSettings, source string) organizationProtocolSettingsResponse {
	out := organizationProtocolSettingsResponse{
		OrganizationID:                   orgID,
		DynamicClientRegistrationEnabled: s.DCREnabled,
		SCIMEnabled:                      s.SCIMEnabled,
		Source:                           source,
	}
	if !s.CreatedAt.IsZero() {
		t := s.CreatedAt
		out.CreatedAt = &t
	}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// organizationVisibleToAdmin reports whether the supplied
// orgID resolves to an existing, non-deleted org. Returns
// true on success; on any failure it writes the appropriate
// envelope (404 for missing or soft-deleted; 500 for repo
// error) and returns false.
//
// The visibility semantic mirrors the existing
// HandleGetOrganization rule: deleted orgs are not addressable
// via admin routes (the admin surface treats deleted-active
// as a single "deleted" state).
func organizationVisibleToAdmin(c *gin.Context, svc *service.OrganizationService, id uuid.UUID) bool {
	org, err := svc.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrOrganizationNotFound()) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return false
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return false
	}
	if org.DeletedAt != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return false
	}
	return true
}

// actorRoleString reports the principal's role for audit
// metadata. Empty when the principal is absent (which should
// not happen behind RequireSiteAdmin but the helper stays
// defensive).
func actorRoleString(c *gin.Context) string {
	p, ok := mw.PrincipalFromContext(c)
	if !ok {
		return ""
	}
	return string(p.Role)
}
