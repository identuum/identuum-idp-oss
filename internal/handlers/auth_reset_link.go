package handlers

// auth_reset_link.go — D9 (owner answer Q-D9 (a)): the public pair
// identuum-ui's /reset-link page calls (CE-UI-2b contract). The token is the
// password reset's; redeeming is PasswordResetService.ResetPassword with the
// page's error vocabulary (invalid_token, weak_password). The raw token is
// never logged: the access log prints the path without its query.

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// HandleValidateResetLink serves GET /api/v1/auth/reset-link/validate?token=:
// {"valid":bool}, without spending the link.
func HandleValidateResetLink(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{"valid": deps.PasswordReset.ValidToken(c.Request.Context(), c.Query("token"))})
	}
}

// HandleRedeemResetLink serves POST /api/v1/auth/reset-link
// {token, new_password}: 200 {"success":true}, 400 weak_password (the link
// stays usable), 400 invalid_token (used, expired or replaced) or 500
// sessions_not_ended (the password is set; the old sign-ins survive).
func HandleRedeemResetLink(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req passwordResetCompleteBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "The request needs token and new_password."})
			return
		}
		err := deps.PasswordReset.ResetPassword(c.Request.Context(), service.ResetPasswordInput{
			Token:       req.Token,
			NewPassword: req.NewPassword,
			IPAddress:   c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
		})
		switch {
		case err == nil:
			c.JSON(http.StatusOK, gin.H{"success": true})
		case errors.Is(err, service.ErrPasswordResetInvalidToken):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token", "message": "This link was used, has expired or was replaced by a newer one. Ask your administrator for a new link."})
		case errors.Is(err, service.ErrPasswordResetWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password", "message": "The password does not meet the organization's password policy."})
		case errors.Is(err, service.ErrPasswordResetRevocationFailed):
			// The password is set and the link spent; a retry would answer
			// invalid_token, so the words must not invite one. Its own code
			// lets the console tell it from a password that was not set. It
			// stays 5xx: the server failed a step the reset owes (the old
			// sign-ins survive), and it is not 503 because no retry helps.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "sessions_not_ended", "message": "Your new password is set, but your other sign-ins could not be ended. Sign in with the new password and ask your administrator to end your other sessions."})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "The password could not be set."})
		}
	}
}
