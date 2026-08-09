package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type selfSessionListResponse struct {
	Sessions []selfSessionView `json:"sessions"`
}

type selfSessionView struct {
	CreatedAt      string  `json:"created_at"`
	ExpiresAt      string  `json:"expires_at"`
	LastSeenAt     *string `json:"last_seen_at,omitempty"`
	UserAgent      *string `json:"user_agent,omitempty"`
	IPAddress      *string `json:"ip_address,omitempty"`
	CurrentSession *bool   `json:"current_session,omitempty"`
}

// HandleListOwnActiveSessions returns safe active-session metadata
// for the authenticated principal. It accepts no user_id input; the
// user_id comes only from mw.PrincipalFromContext.
func HandleListOwnActiveSessions(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
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
		if deps.UserLookup == nil || deps.UserSession == nil {
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
		sessions, err := deps.UserSession.ListActiveUserSessions(c.Request.Context(), principal.UserID)
		if err != nil {
			if errors.Is(err, service.ErrUserSessionInvalidInput) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		out := make([]selfSessionView, 0, len(sessions))
		for _, sess := range sessions {
			if sess == nil {
				continue
			}
			view := selfSessionView{
				CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
				ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
				UserAgent: sess.UserAgent,
				IPAddress: sess.IPAddress,
			}
			if sess.LastUsedAt != nil {
				lastSeen := sess.LastUsedAt.UTC().Format(time.RFC3339)
				view.LastSeenAt = &lastSeen
			}
			if principal.SessionID != uuid.Nil {
				current := sess.ID == principal.SessionID
				view.CurrentSession = &current
			}
			out = append(out, view)
		}
		c.JSON(http.StatusOK, selfSessionListResponse{Sessions: out})
	}
}
