package handlers

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

const selfRevokeAllSessionsReason = "self_revoke_all_sessions"

// HandleRevokeAllOwnSessions revokes all active sessions and OAuth
// refresh tokens for the authenticated principal. There is no
// user-supplied target: body and user_id query inputs are rejected,
// and the user_id comes only from mw.PrincipalFromContext.
func HandleRevokeAllOwnSessions(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if _, present := c.Request.URL.Query()["user_id"]; present || requestHasBody(c) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if deps.UserLookup == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		user, err := deps.UserLookup.GetByID(c.Request.Context(), principal.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		if user == nil || user.ID != principal.UserID || user.Banned || user.DeletedAt != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		sessionErr := deps.SessionRevoker.RevokeUserSessions(
			c.Request.Context(),
			principal.UserID,
			selfRevokeAllSessionsReason,
			map[string]any{
				"organization_id": user.OrganizationID.String(),
			},
		)
		refreshCount, refreshErr := deps.RefreshTokenRevoker.RevokeAllForUser(c.Request.Context(), principal.UserID)

		c.Status(http.StatusNoContent)

		auditMeta := map[string]any{
			"user_id":          principal.UserID.String(),
			"organization_id":  user.OrganizationID.String(),
			"sessions_revoked": sessionErr == nil,
		}
		if refreshErr == nil {
			auditMeta["refresh_tokens_revoked_count"] = refreshCount
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         string(domain.AuditSelfSessionsRevoked),
			Outcome:        "success",
			ActorID:        principal.UserID,
			ActorType:      "user",
			ActorRole:      string(principal.Role),
			OrganizationID: user.OrganizationID,
			SubjectID:      principal.UserID,
			SubjectType:    "user",
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       auditMeta,
		})
	}
}

func requestHasBody(c *gin.Context) bool {
	if c.Request.Body == nil || c.Request.ContentLength == 0 {
		return false
	}
	if c.Request.ContentLength > 0 {
		return true
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(c.Request.Body, 1))
	return n > 0
}
