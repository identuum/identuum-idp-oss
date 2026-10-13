package handlers

// user_reset_link.go — D9 (owner answers Q3 (b) and Q-D9 (a), D-016
// Consequence): POST /api/v1/users/:id/recovery/reset-link returns a one-time
// reset link to the issuing administrator, who hands it to the member; no mail
// is sent. The link opens identuum-ui's /reset-link page (CE-UI-2b contract),
// which checks it with GET /api/v1/auth/reset-link/validate and spends it with
// POST /api/v1/auth/reset-link. The raw link appears only in this answer.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// resetLinkPage is identuum-ui's redeem page for an administrator's link.
const resetLinkPage = "/reset-link"

// auditPasswordResetLinkIssued names the issue in the audit trail (actor,
// subject, organization, expiry; never the link). Spending the link records
// the reset's own user_password_reset_completed.
const auditPasswordResetLinkIssued = "user.password_reset_link_issued"

// PasswordResetLinkIssuer mints the link token; *service.PasswordResetService
// satisfies it.
type PasswordResetLinkIssuer interface {
	IssueLink(ctx context.Context, user *domain.User) (string, time.Time, error)
}

// resetLinkRefusal is one refusal of the issue route: status, code, message.
type resetLinkRefusal struct {
	status        int
	code, message string
}

// resetLinkRefusalFor maps a target refusal; ok is false for an unknown error.
func resetLinkRefusalFor(err error) (resetLinkRefusal, bool) {
	switch {
	case errors.Is(err, domain.ErrUnauthorized):
		return resetLinkRefusal{http.StatusUnauthorized, "unauthorized", "Sign in again."}, true
	case errors.Is(err, domain.ErrCannotResetSelf):
		return resetLinkRefusal{http.StatusForbidden, "cannot_reset_self", "You cannot issue a reset link for your own account. Change your password in your account settings."}, true
	case errors.Is(err, domain.ErrForbidden):
		return resetLinkRefusal{http.StatusForbidden, "forbidden", "You may not issue a reset link for this user."}, true
	case errors.Is(err, service.ErrUserNotFound()), errors.Is(err, domain.ErrUserNotFound):
		return resetLinkRefusal{http.StatusNotFound, "not_found", "No such user."}, true
	case errors.Is(err, service.ErrResetLinkUserDisabled()):
		return resetLinkRefusal{http.StatusConflict, "user_disabled", "This user is disabled. Enable the user first."}, true
	case errors.Is(err, service.ErrResetLinkUserNotActivated()):
		return resetLinkRefusal{http.StatusConflict, "user_not_activated", "This user has not accepted the invitation yet. Send the invite again instead."}, true
	case errors.Is(err, service.ErrResetLinkNoLocalPassword()):
		return resetLinkRefusal{http.StatusConflict, "no_local_password", "This user signs in only through an identity provider and has no password here."}, true
	case errors.Is(err, service.ErrResetLinkLocalPasswordNotAllowed()):
		return resetLinkRefusal{http.StatusConflict, "local_password_not_allowed", "This user's organization allows sign-in only through its identity provider."}, true
	}
	return resetLinkRefusal{}, false
}

// HandleIssuePasswordResetLink serves POST /api/v1/users/:id/recovery/reset-link.
func HandleIssuePasswordResetLink(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id", "message": "The user id is not valid."})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		target, err := deps.UserService.PasswordResetLinkTargetForActor(c.Request.Context(), actor, id)
		if err != nil {
			r, ok := resetLinkRefusalFor(err)
			if !ok {
				r = resetLinkRefusal{http.StatusInternalServerError, "internal_error", "The reset link could not be issued."}
			}
			c.JSON(r.status, gin.H{"error": r.code, "message": r.message})
			return
		}
		// The link opens the UI's page; with no UI base there is no page to
		// open, so nothing is minted (the invite's rule, activation_link.go).
		if uiTokenLink(deps.InviteLinkBaseURL, resetLinkPage, "-") == "" {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "reset_link_unavailable",
				"message": "no reset link can be built because " + activationLinkSettingName + " is not set; set it to the browser-facing base URL of the identuum-ui frontend",
			})
			return
		}
		raw, expiresAt, err := deps.PasswordResetLinks.IssueLink(c.Request.Context(), target)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "The reset link could not be issued."})
			return
		}
		expires := expiresAt.UTC().Format(time.RFC3339)
		c.JSON(http.StatusOK, gin.H{
			"email":      target.Email,
			"reset_url":  uiTokenLink(deps.InviteLinkBaseURL, resetLinkPage, raw),
			"expires_at": expires,
		})
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         auditPasswordResetLinkIssued,
			Outcome:        "success",
			SubjectID:      target.ID,
			SubjectType:    "user",
			OrganizationID: target.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"user_id": target.ID, "organization_id": target.OrganizationID, "expires_at": expires},
		}))
	}
}
