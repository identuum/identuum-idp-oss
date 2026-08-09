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
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OrgActivationResender is the narrow seam HandleResendActivation needs:
// re-issue + re-dispatch a pending org's activation token. Satisfied by
// *service.OrganizationActivationService.
type OrgActivationResender interface {
	ResendActivationToken(ctx context.Context, orgID uuid.UUID) (rawToken string, expiresAt time.Time, adminEmail string, err error)
}

// HandleResendActivation serves POST /api/v1/organizations/:id/resend-activation.
//
// It re-issues a fresh activation token for a pending (not-yet-active)
// organization's org_admin and returns it — the OSS operator retrieval
// path for an unclaimed org whose activation email was lost or never
// wired. The work is delegated to
// OrganizationActivationService.ResendActivationToken, which reuses the
// existing IssueActivationToken send seam: a new token is minted, the old
// one is invalidated (the user's activation_token_hash is overwritten),
// and an email is dispatched when a notifier is wired (OSS runs without
// one and echoes the token in the response instead).
//
// Authority: the route lives in RegisterOrganizationsRoutes' `siteOnly`
// group behind mw.RequireSiteAdmin(), matching the sibling org-lifecycle
// mutations and the admin-authority model — a pending org has no active
// org_admin, so resend is site_admin infrastructure authority. A
// non-site_admin caller (including any org_admin, same-org or cross-org)
// is rejected 403 by the group middleware before this handler runs.
//
// Status mapping (fail-closed; no silent success):
//   - 200 {success, activation_token, admin_email, expires_at} on resend.
//   - 400 {error:"invalid id"} on a non-UUID :id.
//   - 404 {error:"not found"} when the org does not exist, or it exists
//     but has no org_admin to receive the token.
//   - 409 {error:"organization already active"} when the org is already
//     active (activation not applicable).
//   - 503 {error:"activation service unavailable"} when the resend seam
//     is unwired (scaffold deployment).
//   - 500 {error:"internal error"} on a backend failure.
//
// Secret handling: the raw activation token appears ONLY in the response
// body (the documented operator retrieval channel) — it is never logged
// or written to audit metadata. P-018: every path returns; nothing
// panics/exits.
func HandleResendActivation(deps OrganizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		if deps.ActivationResender == nil {
			// Fail closed: the activation service is not wired.
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "activation service unavailable"})
			return
		}
		rawToken, expiresAt, adminEmail, err := deps.ActivationResender.ResendActivationToken(c.Request.Context(), id)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrOrganizationNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, service.ErrOrganizationAlreadyActive):
				c.JSON(http.StatusConflict, gin.H{"error": "organization already active"})
			case errors.Is(err, service.ErrOrganizationActivationNoAdmin):
				c.JSON(http.StatusNotFound, gin.H{"error": "no org_admin to resend activation to"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}

		// Echo the raw token (OSS operator retrieval path). The token is a
		// secret: it appears ONLY in this response body — never in logs or
		// audit metadata.
		c.JSON(http.StatusOK, gin.H{
			"success":          true,
			"activation_token": rawToken,
			"admin_email":      adminEmail,
			"expires_at":       expiresAt.UTC().Format(time.RFC3339),
		})

		// Best-effort audit (P-018). The raw token is deliberately NOT
		// recorded; only identifier-shaped fields.
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "organization.activation_token_resent",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"organization_id": id,
				"admin_email":     adminEmail,
			},
		})
	}
}
