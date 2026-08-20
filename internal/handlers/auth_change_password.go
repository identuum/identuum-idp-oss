package handlers

// auth_change_password.go — OSS handler for the self-service password
// change endpoint POST /api/v1/auth/change-password (THE-V036-PASSWORD).
//
// Authority shape mirrors the /me/mfa surface: mw.RequireAuthenticated
// gates entry and mw.PrincipalFromContext supplies the user_id. There is
// NO user_id parameter on the wire, so cross-user calls are structurally
// impossible (AdminPermissionsModel — this surface is self-service only).
//
// Measured consumer contract (identuum-ui changeOwnPassword +
// e2e/oss-change-password.spec.ts):
//   - request: Authorization: Bearer + JSON {current_password, new_password}
//   - 2xx  → success (the UI ignores the body → 204 No Content)
//   - 400  → policy violation; {message} is safe display text the UI shows
//   - any other non-2xx → the UI shows the generic "check your current
//     password" message, so the wrong-current refusal is 403 (never 400)
//
// R2 — SESSION REVOCATION PARKED (owner ruling DECIDE-LATER, 2026-08-20):
// this handler and its service touch NEITHER sessions NOR refresh tokens.
// A pre-existing session keeps authenticating after the change until R2
// is decided and lands as its own slice.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// changePasswordRequest is the on-the-wire shape. Only these two fields
// are read; any other key is ignored.
type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// HandleChangePassword is the gin handler for POST
// /api/v1/auth/change-password. See the file-header doc for the contract.
func HandleChangePassword(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Failure envelopes must never be cached (same posture as /me/mfa).
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var req changePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if strings.TrimSpace(req.CurrentPassword) == "" || req.NewPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		err := deps.ChangePassword.ChangeOwnPassword(c.Request.Context(), principal.UserID, req.CurrentPassword, req.NewPassword)
		if err != nil {
			var policyErr *service.ChangePasswordPolicyError
			switch {
			case errors.As(err, &policyErr):
				// 400 + message: the ONLY envelope whose message the UI
				// displays verbatim — policy text only, never credential
				// material.
				c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password", "message": policyErr.Detail})
			case errors.Is(err, service.ErrChangePasswordInvalidCurrent):
				// OPAQUE: wrong password, federated account, and no-local-hash
				// all collapse here (non-400 so the UI shows its generic
				// current-password message).
				c.JSON(http.StatusForbidden, gin.H{"error": "invalid_current_password"})
			case errors.Is(err, service.ErrChangePasswordUnauthorized):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		c.Status(http.StatusNoContent)
		// Audit: identifier-shaped metadata only. The passwords, hashes, and
		// bearer material NEVER appear here. R2 parked — deliberately no
		// sessions_revoked / refresh_tokens_revoked keys: nothing was revoked.
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         string(domain.AuditPasswordChanged),
			Outcome:        "success",
			SubjectID:      principal.UserID,
			SubjectType:    "user",
			OrganizationID: principal.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"user_id":         principal.UserID.String(),
				"organization_id": principal.OrganizationID.String(),
				"self_service":    true,
			},
		})
	}
}
