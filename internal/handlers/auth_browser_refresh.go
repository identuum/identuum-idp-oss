package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// HandleBrowserSessionRefresh is mounted only behind the UI boundary's
// same-origin and request-header checks. Credentials enter and leave in
// HttpOnly cookies; the browser never receives a token response body.
func HandleBrowserSessionRefresh(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if deps.UserSession == nil || deps.UserToken == nil || deps.UserLookup == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "refresh_unavailable"})
			return
		}
		raw, err := c.Cookie("refresh_token")
		if err != nil || raw == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"reason": "missing_refresh_credential"})
			return
		}
		ctx := c.Request.Context()
		issued, err := deps.UserSession.RotateRefreshToken(ctx, raw)
		if errors.Is(err, service.ErrUserSessionInvalidGrant) {
			// A CAS loser can re-read the committed winner's predecessor
			// state once. The service still judges expiry, revocation, reuse
			// and account status; no error is converted into acceptance here.
			issued, err = deps.UserSession.RotateRefreshToken(ctx, raw)
		}
		if err != nil {
			recordSessionRefreshReuse(c, deps.Audit, err)
			if errors.Is(err, service.ErrUserSessionUnavailable) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "refresh_unavailable"})
			} else if errors.Is(err, service.ErrUserSessionInvalidGrant) || errors.Is(err, service.ErrUserSessionReuse) {
				c.JSON(http.StatusUnauthorized, gin.H{"reason": "refresh_refused"})
			} else {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "refresh_unavailable"})
			}
			return
		}
		user, err := deps.UserLookup.GetByID(ctx, issued.Session.UserID)
		if err != nil || user == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "refresh_unavailable"})
			return
		}
		if user.Banned || user.DeletedAt != nil || user.ID != issued.Session.UserID {
			c.JSON(http.StatusUnauthorized, gin.H{"reason": "refresh_refused"})
			return
		}
		access, err := deps.UserToken.IssueForSession(ctx, user, issued.Session)
		if err != nil || access == nil || access.AccessToken == "" || ctx.Err() != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "refresh_unavailable"})
			return
		}
		if deps.Audit != nil {
			_ = deps.Audit.Record(ctx, audit.Event{
				Action: "user_session.refresh.success", Outcome: "success",
				IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent(),
			})
		}
		refresh := issued.RefreshToken
		if refresh == raw {
			// Grace acceptance holds the predecessor, not the winner's new
			// secret. Never overwrite a newer cookie with that predecessor.
			refresh = ""
		}
		setAuthCookies(c, access.AccessToken, refresh, issued.Session.RememberMe)
		c.Status(http.StatusNoContent)
	}
}
