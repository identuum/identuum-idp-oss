package handlers

import (
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

const selfRevokeOtherSessionsReason = "self_revoke_other_sessions"

// HandleRevokeOtherOwnSessions revokes the authenticated principal's
// other active browser sessions while preserving the current session.
// There is no user-supplied target: body and query inputs are rejected,
// and the user/session identity comes only from mw.PrincipalFromContext.
func HandleRevokeOtherOwnSessions(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil || principal.SessionID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if len(c.Request.URL.Query()) > 0 || requestHasBody(c) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if deps.UserLookup == nil || deps.UserSession == nil || deps.SessionLookup == nil {
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
		current, err := deps.SessionLookup.GetByID(c.Request.Context(), principal.SessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		if current == nil || current.UserID != principal.UserID || !current.IsValid || current.RevokedAt != nil || !current.ExpiresAt.After(time.Now().UTC()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		sessions, err := deps.UserSession.ListActiveUserSessions(c.Request.Context(), principal.UserID)
		if err != nil {
			if errors.Is(err, service.ErrUserSessionInvalidInput) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		revoked := 0
		for _, session := range sessions {
			if session == nil || session.UserID != principal.UserID || session.ID == principal.SessionID {
				continue
			}
			if err := deps.UserSession.RevokeSession(c.Request.Context(), session.ID, selfRevokeOtherSessionsReason); err != nil {
				if errors.Is(err, service.ErrUserSessionInvalidInput) {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
				return
			}
			revoked++
		}
		c.Status(http.StatusNoContent)

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
			Metadata: map[string]any{
				"user_id":                principal.UserID.String(),
				"organization_id":        user.OrganizationID.String(),
				"scope":                  "other_sessions",
				"sessions_revoked_count": revoked,
			},
		})
	}
}
