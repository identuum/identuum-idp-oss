package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// orgAdminRecoveryCandidate is the per-candidate wire shape returned by
// GET /api/v1/organizations/:id/admin-recovery-candidates.
//
// It mirrors the CE reference contract field-for-field (identuum-idp-ce
// cmd/identuum-idp/api_v1_organizations_admins_handlers.go
// apiV1OrgAdminCandidate) so the bundled identuum-ui org-detail
// "administrators recovery card" reads an identical shape from either
// edition. OSS fills mfa_enabled / email_verified / last_login_at from
// real columns where the CE reference emitted schema-shape placeholders;
// the field names and semantics are unchanged.
type orgAdminRecoveryCandidate struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	Role          string `json:"role"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	EmailVerified bool   `json:"email_verified"`
	Active        bool   `json:"active"`
	Deleted       bool   `json:"deleted"`
	CreatedAt     string `json:"created_at,omitempty"`
	LastLoginAt   string `json:"last_login_at,omitempty"`
}

// orgAdminRecoveryResponse is the ok-branch envelope: {admins:[...]}.
// The wrapper matches the CE reference's apiV1OrgAdminRecoveryResponse
// so future sibling fields (e.g. recovery-window metadata) can fold in
// without breaking the UI's narrow projection.
type orgAdminRecoveryResponse struct {
	Admins []orgAdminRecoveryCandidate `json:"admins"`
}

// orgAdminRecoveryPageSize is the per-page fan of the org-member scan.
// repository.NewPagination caps page size at 100, so the handler pages
// through the full membership (see orgAdminRecoveryMaxPages) instead of
// silently truncating an org's admins at a single page.
const orgAdminRecoveryPageSize = 100

// orgAdminRecoveryMaxPages hard-bounds the pagination loop so a
// misbehaving lister can never spin the serving goroutine forever
// (P-018: no unbounded work on a serving path). 100 * 10000 = 1,000,000
// members scanned before the backstop trips — far beyond any real org.
const orgAdminRecoveryMaxPages = 10000

// orgAdminRecoveryRFC3339 is the timestamp layout for the wire shape,
// matching the CE reference's rfc3339Layout.
const orgAdminRecoveryRFC3339 = "2006-01-02T15:04:05Z07:00"

// HandleListOrgAdminRecoveryCandidates serves
// GET /api/v1/organizations/:id/admin-recovery-candidates.
//
// This is the OSS port of the CE reference handler
// (identuum-idp-ce HandleAPIV1OrgAdminRecoveryList): a site_admin-only
// operator-recovery surface that lists the org_admin accounts of one
// tenant organization so an operator can drive the reset-MFA recovery
// flow from the org-detail card. It carries NO license gate — CE mounts
// it unconditionally; the split parity matrix classifies it OSS-tier.
// Porting it here resolves the F4 contradiction where the matrix
// asserted OSS parity while OSS still returned 501.
//
// Authority: the route lives in RegisterOrganizationsRoutes' `siteOnly`
// group behind mw.RequireSiteAdmin(); a non-site_admin caller is
// rejected 403 by the group middleware before this handler runs —
// consistent with the sibling create/update/delete org routes. The
// handler adds no second role check (the gate is the group's).
//
// Contract (matches the CE reference):
//   - 200 {admins:[...]} for an existing tenant org (empty array — NOT
//     an error — when the org has no org_admin rows).
//   - 400 {error:"invalid id"} on a non-UUID :id.
//   - 404 {error:"not found"} when no org matches :id, or :id is the
//     System Organization sentinel (infrastructure, never surfaced).
//   - 503 {error:"user directory unavailable"} when the member-lister
//     seam is unwired (scaffold deployment).
//   - 500 {error:"internal error"} on a backend read failure.
//
// P-018: every failure path returns a JSON error — no panic/Fatal/Exit.
func HandleListOrgAdminRecoveryCandidates(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		// System Org is infrastructure authority, never surfaced through
		// the tenant org tree — mirrors the CE reference's sentinel guard.
		// SystemOrgID is a canonical lowercase UUID string constant, so
		// compare against the parsed id's String() form.
		if id.String() == domain.SystemOrgID {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// Resolve the org so a missing org is an honest 404 rather than an
		// empty candidate list. Prefer the service; fall back to the repo,
		// matching HandleGetOrganization.
		var o *domain.Organization
		switch {
		case deps.OrganizationService != nil:
			o, err = deps.OrganizationService.GetByID(c.Request.Context(), id)
		case deps.OrganizationRepo != nil:
			o, err = deps.OrganizationRepo.GetByID(c.Request.Context(), id)
		}
		if err != nil || o == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		// MemberLister enumerates org members (wired from UserService in
		// production). Fail closed + honest when unwired rather than
		// returning a misleading empty list.
		if deps.MemberLister == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user directory unavailable"})
			return
		}

		admins := make([]orgAdminRecoveryCandidate, 0)
		seen := 0
		for page := 1; page <= orgAdminRecoveryMaxPages; page++ {
			opts := repository.ListUserOptions{
				Pagination: repository.NewPagination(page, orgAdminRecoveryPageSize),
				Sort:       repository.NewUserSort("created_at", true),
			}
			users, total, lerr := deps.MemberLister.ListByOrganization(c.Request.Context(), id, opts)
			if lerr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}
			for _, u := range users {
				// Strict org_admin filter. domain.User.IsOrgAdmin() ALSO
				// reports true for site_admin, which must NOT appear as a
				// tenant recovery candidate — so match on the role constant
				// exactly, as the CE reference's isOrgAdminUserSummary does.
				if u != nil && u.Role == domain.RoleOrgAdmin {
					admins = append(admins, toOrgAdminRecoveryCandidate(u))
				}
			}
			seen += len(users)
			// Stop when the page came back short (data exhausted) or the
			// running count has reached the reported total.
			if len(users) < orgAdminRecoveryPageSize || seen >= total {
				break
			}
		}

		c.JSON(http.StatusOK, orgAdminRecoveryResponse{Admins: admins})
	}
}

// toOrgAdminRecoveryCandidate projects an OSS domain.User onto the
// CE-compatible candidate wire shape. Field semantics track the CE
// reference: active = enabled AND not soft-deleted; deleted = soft-
// deleted. Unlike the CE reference (whose local_users schema lacked the
// columns), OSS emits real mfa_enabled / email_verified / last_login_at
// values. Only org_admin rows reach this projection (see the caller's
// strict role filter), so Role is fixed to the org_admin constant.
func toOrgAdminRecoveryCandidate(u *domain.User) orgAdminRecoveryCandidate {
	cand := orgAdminRecoveryCandidate{
		ID:            u.ID.String(),
		Email:         u.Email,
		Role:          string(domain.RoleOrgAdmin),
		MFAEnabled:    u.MFAEnabled,
		EmailVerified: u.EmailVerified,
		Active:        !u.Banned && u.DeletedAt == nil,
		Deleted:       u.DeletedAt != nil,
	}
	if u.Name != nil {
		cand.Name = *u.Name
	}
	if !u.CreatedAt.IsZero() {
		cand.CreatedAt = u.CreatedAt.UTC().Format(orgAdminRecoveryRFC3339)
	}
	if u.LastLoginAt != nil && !u.LastLoginAt.IsZero() {
		cand.LastLoginAt = u.LastLoginAt.UTC().Format(orgAdminRecoveryRFC3339)
	}
	return cand
}
