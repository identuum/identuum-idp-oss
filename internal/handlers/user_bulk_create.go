package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// maxBulkCreateUsers caps a single bulk-create batch. A batch that is
// empty or exceeds this is rejected whole (400) before any user is
// created — matching the ancestor's pre-processing count guard.
const maxBulkCreateUsers = 50

// bulkUserEntry is one row of a bulk-create batch. Its fields mirror the
// single-create request exactly so each row goes through the IDENTICAL
// create path (no weaker fork).
type bulkUserEntry struct {
	OrganizationID uuid.UUID       `json:"organization_id"`
	Email          string          `json:"email"`
	Password       string          `json:"password"`
	Name           string          `json:"name,omitempty"`
	Role           domain.UserRole `json:"role"`
}

type bulkCreateUsersRequest struct {
	Users []bulkUserEntry `json:"users"`
}

// bulkFailedItem is the per-row failure record. Reason is a sanitized,
// non-leaking category (see safeBulkReason) — never a raw internal error.
type bulkFailedItem struct {
	Index  int    `json:"index"`
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// bulkCreateUsersResponse is the synchronous best-effort result: the safe
// projections of the users that were created, plus the per-row failures.
// Succeeded users are NOT rolled back when a later row fails (the batch is
// not transactional).
type bulkCreateUsersResponse struct {
	Created      []safeUser       `json:"created"`
	Failed       []bulkFailedItem `json:"failed"`
	CreatedCount int              `json:"created_count"`
	FailedCount  int              `json:"failed_count"`
}

// HandleBulkCreateUsers serves POST /api/v1/users/bulk — the synchronous,
// best-effort OSS bulk-create (the ancestor used an async JobService;
// OSS has no job infra, so this processes inline and returns per-row
// results directly).
//
// Each row is created through the SAME UserService.CreateUserForActor the
// single POST /users route uses — so every row gets identical validation,
// password-policy, secure defaults, org-scoping (org_admin forced to own
// org; org_admin cannot create a site_admin), and a UUIDv7 id minted
// inside UserService.Create via internal/utils/uuidgen.NewV7. Bulk grants
// no privilege the single route lacks.
//
// Authorization: the route lives in the same ScopeUsersCreate-gated group
// as POST /users (RequireSiteAdminOrOrgAdminWithScopesAudit); a caller
// without the scope is rejected 403/401 by the group middleware, and an
// org_admin cannot bulk into another tenant (enforced per-row by
// CreateUserForActor).
//
// Semantics:
//   - the batch must hold 1..50 rows; empty or >50 → 400, nothing created.
//   - best-effort: a row's failure (bad input, duplicate email, forbidden
//     target) is recorded in `failed` and the batch continues; succeeded
//     rows are never rolled back.
//   - 200 with {created, failed, created_count, failed_count}.
//
// Safe projection: created rows are the safeUser DTO (never password
// hashes/secrets); failure reasons are sanitized categories. P-018: no
// panic/exit — every row's error becomes a failed-item and the handler
// always returns a well-formed result.
func HandleBulkCreateUsers(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req bulkCreateUsersRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		// Cap the batch before touching any row.
		if len(req.Users) == 0 || len(req.Users) > maxBulkCreateUsers {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":  "invalid request",
				"reason": "users must contain between 1 and 50 entries",
			})
			return
		}

		actor, _ := mw.PrincipalFromContext(c)

		created := make([]safeUser, 0, len(req.Users))
		failed := make([]bulkFailedItem, 0)
		for i, u := range req.Users {
			// Per-row target org for the password policy (rows may name
			// different orgs); nil-safe like the single-create path.
			policyOrgID := u.OrganizationID
			if policyOrgID == uuid.Nil && actor != nil {
				policyOrgID = actor.OrganizationID
			}
			pce, minLen := resolveOrgPasswordPolicy(c.Request.Context(), deps.PolicyOrgs, policyOrgID)
			out, err := deps.UserService.CreateUserForActor(c.Request.Context(), actor, service.CreateUserOptions{
				OrganizationID:            u.OrganizationID,
				Email:                     u.Email,
				Password:                  u.Password,
				Name:                      u.Name,
				Role:                      u.Role,
				PasswordComplexityEnabled: pce,
				MinPasswordLength:         minLen,
			})
			if err != nil {
				// Best-effort: record and continue; no abort, no rollback.
				failed = append(failed, bulkFailedItem{Index: i, Email: u.Email, Reason: safeBulkReason(err)})
				continue
			}
			created = append(created, toSafeUser(out))
			// Per-row audit, matching the single-create route. Metadata is
			// identifier-shaped only — never password or password_hash.
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user.created",
				Outcome:   "success",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				Metadata: map[string]any{
					"user_id":         out.ID,
					"email":           out.Email,
					"role":            string(out.Role),
					"organization_id": out.OrganizationID,
					"bulk":            true,
				},
			})
		}

		c.JSON(http.StatusOK, bulkCreateUsersResponse{
			Created:      created,
			Failed:       failed,
			CreatedCount: len(created),
			FailedCount:  len(failed),
		})
	}
}

// safeBulkReason maps a create error to a per-row reason that never leaks
// internal detail (password-hashing failures, DB internals). It mirrors
// the single-create route's non-leaking posture — forbidden vs a generic
// "invalid request" for validation failures — plus the safe
// duplicate-user sentinel.
func safeBulkReason(err error) string {
	switch {
	case errors.Is(err, domain.ErrForbidden):
		return "forbidden"
	case errors.Is(err, domain.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, domain.ErrUserAlreadyExists):
		return "email already exists"
	default:
		return "invalid request"
	}
}
