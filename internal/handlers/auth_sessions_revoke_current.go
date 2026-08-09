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

const selfRevokeCurrentSessionReason = "self_revoke_current_session"

// HandleRevokeCurrentOwnSession revokes only the authenticated
// principal's current browser session. There is no user-supplied target:
// body and query inputs are rejected, and the session id comes only from
// mw.PrincipalFromContext.
func HandleRevokeCurrentOwnSession(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
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
		session, err := deps.SessionLookup.GetByID(c.Request.Context(), principal.SessionID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		if session == nil || session.UserID != principal.UserID || !session.IsValid || session.RevokedAt != nil || !session.ExpiresAt.After(time.Now().UTC()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if err := deps.UserSession.RevokeSession(c.Request.Context(), principal.SessionID, selfRevokeCurrentSessionReason); err != nil {
			if errors.Is(err, service.ErrUserSessionInvalidInput) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.Status(http.StatusNoContent)

		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         string(domain.AuditSessionRevoked),
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
				"user_id":         principal.UserID.String(),
				"organization_id": user.OrganizationID.String(),
				"scope":           "current_session",
			},
		})
	}
}
