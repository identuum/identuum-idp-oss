package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// organizationExportCandidate is the safe per-organization projection
// returned by GET /api/v1/organizations/export-candidates, for
// cross-system (IDP -> AG) organization linking/import planning.
//
// This is DELIBERATELY NOT the Enterprise/CE SIEM audit-export feature
// (features.AuditExport / the `audit:export` scope) — it is a narrow,
// read-only organization listing, unrelated in both purpose and field
// set. Ported from the ancestor monolith's
// HandleListOrganizationExportCandidates (identuum-idp
// internal/handlers/handler_organization_export.go), which was
// RBAC-scope-gated (ScopeOrgsRead), not license-gated.
//
// Field set is explicit and intentionally narrow: no users, org
// admins, passwords, MFA secrets, role bindings, sessions, tokens,
// licenses, audit rows, or any other org policy/internal field is
// included. Adding a field here requires a deliberate decision, not an
// accidental struct-dump — see toOrganizationExportCandidate.
type organizationExportCandidate struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Slug            string    `json:"slug"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	SourceComponent string    `json:"source_component"`
}

// toOrganizationExportCandidate projects domain.Organization onto the
// safe export shape. Every other field on domain.Organization (auth
// policy, MFA policy, session limits, SCIM sync state, password
// complexity, registration policy, and all other internal/policy
// flags) is intentionally omitted.
func toOrganizationExportCandidate(o *domain.Organization) organizationExportCandidate {
	if o == nil {
		return organizationExportCandidate{}
	}
	return organizationExportCandidate{
		ID:              o.ID,
		Name:            o.Name,
		Slug:            o.OrgSlug,
		Status:          exportCandidateStatus(o),
		CreatedAt:       o.CreatedAt,
		UpdatedAt:       o.UpdatedAt,
		SourceComponent: "identuum-idp",
	}
}

// exportCandidateStatus derives a stable status string, matching the
// ancestor's organizationStatusLabel. The active repository.List call
// this handler makes always excludes deleted rows, so "deleted" is
// defense-in-depth rather than an expected value today.
func exportCandidateStatus(o *domain.Organization) string {
	if o.DeletedAt != nil {
		return "deleted"
	}
	if !o.Active {
		return "disabled"
	}
	return "active"
}

// HandleListOrganizationExportCandidates serves
// GET /api/v1/organizations/export-candidates. Mounted under the same
// listGroup (mw.RequireSiteAdminOrOrgAdminWithScopesAudit with
// ScopeOrgsRead) as the sibling GET /api/v1/organizations list route —
// same gate, same actor-scoping pattern: an org_admin sees only their
// own org (single-row); site_admin sees every non-deleted org
// (active and inactive/"shell" orgs both included, matching the
// ancestor's "site_admin needs to see all orgs that may be candidates
// for linking" intent). An actor lacking the scope never reaches this
// handler — the middleware rejects with 401/403 first.
func HandleListOrganizationExportCandidates(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		pageSize := parsePositiveQuery(c, "page_size", 50, 200)
		page := parsePositiveQuery(c, "page", 1, 1<<16)
		pagination := repository.NewPagination(page, pageSize)
		sort := repository.NewOrganizationSort("name", false)
		actor, _ := mw.PrincipalFromContext(c)

		// org_admin path: return only own org as a single-row list —
		// mirrors HandleListOrganizations so this route never becomes
		// a new cross-tenant enumeration surface for org_admin actors.
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
					"organizations": []organizationExportCandidate{},
					"total":         0,
					"page":          page,
					"page_size":     pageSize,
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"organizations": []organizationExportCandidate{toOrganizationExportCandidate(o)},
				"total":         1,
				"page":          page,
				"page_size":     pageSize,
			})
			return
		}

		// site_admin / fallback: cross-tenant list. IncludeInactive
		// surfaces active AND inactive ("shell") orgs — only deleted
		// orgs (and the System Org, excluded unconditionally by the
		// repository) are left out, matching the ancestor's intent.
		filter := repository.OrganizationFilter{IncludeInactive: true}
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
		out := make([]organizationExportCandidate, 0, len(orgs))
		for _, o := range orgs {
			out = append(out, toOrganizationExportCandidate(o))
		}
		c.JSON(http.StatusOK, gin.H{
			"organizations": out,
			"total":         total,
			"page":          page,
			"page_size":     pageSize,
		})
	}
}
