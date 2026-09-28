package handlers

// user_invite.go — OSS-ONBOARD-A (owner ruling D-016): the HTTP side of the
// user invite.
//
//   - POST /api/v1/users with no password (HandleCreateUser → handleInviteUser):
//     201 {user, invite_token, invite_url | invite_url_unavailable, expires_at}.
//   - POST /api/v1/users/:id/invite: re-issue, 200 {email, invite_token,
//     invite_url | invite_url_unavailable, expires_at}; 409 when the user is
//     not pending.
//   - GET /api/v1/auth/invite/:token and POST /api/v1/auth/invite (public):
//     validate and redeem. Unknown, expired and spent share one answer,
//     400 {"error":"invalid_token"}.
//
// The raw token appears only in the issuing response bodies; no log line
// and no audit row carries it.

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

func handleInviteUser(c *gin.Context, deps UsersHandlerDeps, actor *domain.Principal, opts service.CreateUserOptions) {
	created, raw, expiresAt, err := deps.UserService.InviteUserForActor(c.Request.Context(), actor, opts)
	if errors.Is(err, domain.ErrForbidden) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if errors.Is(err, domain.ErrUnauthorized) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	body := gin.H{
		"user":         toSafeUser(created),
		"invite_token": raw,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
	}
	applyInviteLinkFields(body, deps.InviteLinkBaseURL, raw)
	c.JSON(http.StatusCreated, body)
	_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
		Action:         "user.invited",
		Outcome:        "success",
		SubjectID:      created.ID,
		SubjectType:    "user",
		OrganizationID: created.OrganizationID,
		IPAddress:      c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
		Metadata: map[string]any{
			"user_id":         created.ID,
			"email":           created.Email,
			"role":            string(created.Role),
			"organization_id": created.OrganizationID,
		},
	}))
}

// HandleReissueUserInvite serves POST /api/v1/users/:id/invite.
func HandleReissueUserInvite(deps UsersHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		actor, _ := mw.PrincipalFromContext(c)
		user, raw, expiresAt, err := deps.UserService.ReissueInviteForActor(c.Request.Context(), actor, id)
		if err != nil {
			switch {
			case errors.Is(err, domain.ErrUnauthorized):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			case errors.Is(err, domain.ErrForbidden):
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			case errors.Is(err, service.ErrUserNotFound()):
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			case errors.Is(err, service.ErrUserNotPendingInvite()):
				c.JSON(http.StatusConflict, gin.H{"error": "user_not_pending"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			}
			return
		}
		body := gin.H{
			"email":        user.Email,
			"invite_token": raw,
			"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		}
		applyInviteLinkFields(body, deps.InviteLinkBaseURL, raw)
		c.JSON(http.StatusOK, body)
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         "user.invite_reissued",
			Outcome:        "success",
			SubjectID:      user.ID,
			SubjectType:    "user",
			OrganizationID: user.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"user_id": user.ID, "organization_id": user.OrganizationID},
		}))
	}
}

// HandleValidateUserInvite serves GET /api/v1/auth/invite/:token (public):
// 200 {success, email} for a live invite, else 400 invalid_token. It does
// not spend the token.
func HandleValidateUserInvite(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		user, err := deps.UserInvite.ValidateInvite(c.Request.Context(), c.Param("token"))
		if err != nil {
			respondInviteError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "email": user.Email})
	}
}

// HandleRedeemUserInvite serves POST /api/v1/auth/invite (public)
// {token, password}: 200 {success} when the password is set, the user
// verified and the token spent; 400 weak_password (the token stays
// usable) or invalid_token. No session is minted: the user signs in next,
// and MFA follows the organization's policy there.
func HandleRedeemUserInvite(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var req struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		user, err := deps.UserInvite.RedeemInvite(c.Request.Context(), req.Token, req.Password)
		if err != nil {
			respondInviteError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true})
		if deps.Audit != nil {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:         "user.invite_redeemed",
				Outcome:        "success",
				ActorID:        user.ID,
				ActorType:      "user",
				ActorEmail:     user.Email,
				SubjectID:      user.ID,
				SubjectType:    "user",
				OrganizationID: user.OrganizationID,
				IPAddress:      c.ClientIP(),
				UserAgent:      c.Request.UserAgent(),
				Metadata:       map[string]any{"user_id": user.ID, "organization_id": user.OrganizationID},
			})
		}
	}
}

func respondInviteError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInviteWeakPassword()):
		c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password"})
	case errors.Is(err, service.ErrInviteInvalid()):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
	case errors.Is(err, service.ErrInviteUnavailable()):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "invite_unavailable"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
	}
}
