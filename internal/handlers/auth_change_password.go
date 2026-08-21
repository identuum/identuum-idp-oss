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
// R2 — RULED 2026-08-21: a successful password change REVOKES all the
// user's OTHER sessions and ALL OAuth refresh tokens; the session making
// the change STAYS VALID. The fan-out reuses the measured primitives:
// the revoke-others loop (ListActiveUserSessions + RevokeSession, skipping
// principal.SessionID — the same shape as /me/sessions/revoke-others) and
// RefreshTokenRevoker.RevokeAllForUser. Revocation runs AFTER the hash
// commit and is warn-and-continue (the mfa-disable contract): the password
// HAS changed at that point, so a revocation hiccup must not make the UI
// claim the change failed — the audit row records exactly what happened.

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

// changePasswordRevokeReason is the revocation reason stamped on every
// OTHER session killed by a successful password change (R2).
const changePasswordRevokeReason = "password_changed"

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
		// R2 fan-out (ruled 2026-08-21): revoke every OTHER session — the
		// changing session stays valid — plus ALL OAuth refresh tokens.
		// Warn-and-continue: the hash is already rotated, so failures are
		// recorded in the audit metadata rather than failing the response.
		revokedSessions := 0
		sessionsClean := true
		if deps.UserSession != nil && principal.SessionID != uuid.Nil {
			sessions, listErr := deps.UserSession.ListActiveUserSessions(c.Request.Context(), principal.UserID)
			if listErr != nil {
				sessionsClean = false
			} else {
				for _, s := range sessions {
					if s == nil || s.UserID != principal.UserID || s.ID == principal.SessionID {
						continue
					}
					if err := deps.UserSession.RevokeSession(c.Request.Context(), s.ID, changePasswordRevokeReason); err != nil {
						sessionsClean = false
						continue
					}
					revokedSessions++
				}
			}
		} else if principal.SessionID == uuid.Nil {
			// A session-less principal (pure token) has nothing to preserve:
			// revoke ALL sessions via the existing best-effort seam.
			if err := deps.SessionRevoker.RevokeUserSessions(c.Request.Context(), principal.UserID,
				changePasswordRevokeReason, map[string]any{
					"organization_id": principal.OrganizationID.String(),
				}); err != nil {
				sessionsClean = false
			}
		}
		refreshCount, refreshErr := deps.RefreshTokenRevoker.RevokeAllForUser(c.Request.Context(), principal.UserID)
		c.Status(http.StatusNoContent)
		// Audit: identifier-shaped metadata only. The passwords, hashes, and
		// bearer material NEVER appear here.
		auditMeta := map[string]any{
			"user_id":                   principal.UserID.String(),
			"organization_id":           principal.OrganizationID.String(),
			"self_service":              true,
			"other_sessions_revoked":    revokedSessions,
			"session_revocation_clean":  sessionsClean,
			"current_session_preserved": principal.SessionID != uuid.Nil,
		}
		if refreshErr == nil {
			auditMeta["refresh_tokens_revoked_count"] = refreshCount
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         string(domain.AuditPasswordChanged),
			Outcome:        "success",
			SubjectID:      principal.UserID,
			SubjectType:    "user",
			OrganizationID: principal.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       auditMeta,
		})
	}
}
