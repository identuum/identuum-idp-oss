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

// HandleApproveUser serves POST /api/v1/users/:id/approve — the OSS
// completion of the public_registration approval flow.
//
// A self-registered user is held pending as banned=true + role=org_user;
// approval clears that hold (banned=false) so the login path — which
// rejects banned users — will accept the account. Approval is
// specifically the registration-hold clear, NOT a general un-ban:
// UserService.ApproveRegistrationForActor rejects any target that is not
// in the exact pending shape.
//
// Authorization uses the same scope-gated pattern as the sibling update
// route: the caller is gated at the route group by
// RequireSiteAdminOrOrgAdminWithScopesAudit(..., ScopeUsersUpdate), and
// the service layer additionally enforces the actor→target authority
// (site_admin over any target; org_admin over same-org non-site_admin
// targets only).
//
// Status mapping (fail-closed; no silent success):
//   - 200 + safe user projection on approval.
//   - 400 {error:"invalid id"} on a non-UUID :id.
//   - 401 {error:"unauthorized"} when the actor baseline is missing.
//   - 403 {error:"forbidden"} when the actor lacks authority over the
//     target (e.g. org_admin cross-org, or an org_admin targeting a
//     site_admin).
//   - 404 {error:"not found"} when no user matches :id.
//   - 409 {error:"user is not pending registration approval"} when the
//     target is not a held self-registrant (already-active user, admin).
//   - 500 {error:"internal error"} on a backend failure.
//
// P-018: every path returns a JSON response; nothing panics/exits.
func HandleApproveUser(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		updated, err := deps.UserService.ApproveRegistrationForActor(c.Request.Context(), actor, id)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrUnauthorized):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			case errors.Is(err, domain.ErrForbidden):
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			case errors.Is(err, service.ErrUserNotFound()):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, service.ErrUserNotPendingApproval()):
				c.JSON(http.StatusConflict, gin.H{"error": "user is not pending registration approval"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}

		c.JSON(http.StatusOK, toSafeUser(updated))

		// Best-effort audit (P-018: a record failure never breaks the
		// approval). Actor identity is identifier-shaped only — never a
		// token, secret, password, or session id.
		auditMeta := map[string]any{
			"user_id":         updated.ID,
			"organization_id": updated.OrganizationID,
		}
		if actor != nil {
			auditMeta["actor_role"] = string(actor.Role)
			if actor.UserID != uuid.Nil {
				auditMeta["actor_user_id"] = actor.UserID
			}
			if actor.OrganizationID != uuid.Nil {
				auditMeta["actor_organization_id"] = actor.OrganizationID
			}
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user.registration_approved",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata:  auditMeta,
		})
	}
}
