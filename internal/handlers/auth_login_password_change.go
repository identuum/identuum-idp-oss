package handlers

// auth_login_password_change.go — the required password change of a sign-in
// (OSS-FIN-1, owner ruling D-017). A user created with an admin-set password
// answers POST /api/v1/auth/login with 401 password_change_required and a
// one-time session_id. POST /api/v1/auth/login/password-change redeems it
// with the new password (organization policy; not the admin-set one), then
// the sign-in continues exactly as a password sign-in would: MFA enrolment
// or verification when the policy asks (a new handle), else the session.
// Nothing issued before the change is a credential.

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type loginPasswordChangeRequest struct {
	SessionID   string `json:"session_id"`
	NewPassword string `json:"new_password"`
}

// auditLoginStep records a denied sign-in step with the user's id only.
func auditLoginStep(c *gin.Context, svc audit.Service, action string, result *service.LoginResult) {
	meta := map[string]any{}
	ev := audit.Event{
		Action:    action,
		Outcome:   "denied",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata:  meta,
	}
	if result != nil && result.User != nil {
		meta["user_id"] = result.User.ID.String()
		// OSS-FIN-3: the password is proven, so the step is the user's own —
		// not anonymous — and concerns the user's organization.
		ev.ActorType = audit.ActorTypeUser
		ev.ActorID = result.User.ID
		ev.ActorEmail = result.User.Email
		ev.ActorRole = string(result.User.Role)
		ev.OrganizationID = result.User.OrganizationID
	}
	_ = svc.Record(c.Request.Context(), ev)
}

// changeRequiredPassword runs the shared change for both sign-in surfaces:
// peek the handle, change (policy, reuse, single winner), claim the handle,
// audit. Returns the user (with org projections) and the remember-me choice.
// A *service.ChangePasswordPolicyError leaves the handle usable.
func changeRequiredPassword(c *gin.Context, mfa *service.MFAEnrollmentService, change *service.ChangePasswordService, auditSvc audit.Service, handle, newPassword string) (*domain.User, bool, error) {
	id, err := uuid.Parse(handle)
	if err != nil {
		return nil, false, service.ErrMFAEnrollmentInvalid
	}
	userID, remember, err := mfa.PeekPasswordChange(c.Request.Context(), id)
	if err != nil {
		return nil, false, err
	}
	user, err := change.ChangeRequiredAtSignIn(c.Request.Context(), userID, newPassword)
	if err != nil {
		return nil, false, err
	}
	if err := mfa.ConsumePasswordChange(c.Request.Context(), id); err != nil {
		return nil, false, err
	}
	_ = auditSvc.Record(c.Request.Context(), audit.Event{
		Action:    "user_session.login.password_changed",
		Outcome:   "success",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Metadata:  map[string]any{"user_id": user.ID.String()},
	})
	return user, remember, nil
}

// HandleLoginPasswordChange serves POST /api/v1/auth/login/password-change.
func HandleLoginPasswordChange(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if refuseCrossSiteCredentialPost(c) {
			return
		}
		var req loginPasswordChangeRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.SessionID == "" || req.NewPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		user, remember, err := changeRequiredPassword(c, deps.MFAEnrollment, deps.ChangePassword, deps.Audit, req.SessionID, req.NewPassword)
		var policy *service.ChangePasswordPolicyError
		switch {
		case errors.As(err, &policy):
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password", "message": policy.Detail})
			return
		case err != nil:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_session"})
			return
		}
		// Continue the sign-in with the new password proven: the MFA gate
		// Login would have applied, then the session.
		result := &service.LoginResult{User: user}
		switch {
		case service.IsMFARequiredForUser(user) && !user.MFAEnabled:
			body := gin.H{"error": "mfa_enrollment_required", "mfa_required": true, "mfa_enrollment_required": true}
			if h := mintPendingMFAHandle(c, deps, result, domain.MFAPendingKindEnroll, remember); h != "" {
				body["session_id"] = h
			}
			auditLoginStep(c, deps.Audit, "user_session.login.mfa_enrollment_required", result)
			c.JSON(http.StatusUnauthorized, body)
		case user.MFAEnabled:
			body := gin.H{"error": "mfa_required", "mfa_required": true, "mfa_enrollment_required": false}
			if h := mintPendingMFAHandle(c, deps, result, domain.MFAPendingKindVerify, remember); h != "" {
				body["session_id"] = h
			}
			auditLoginStep(c, deps.Audit, "user_session.login.mfa_required", result)
			c.JSON(http.StatusUnauthorized, body)
		default:
			completeMFALogin(c, deps, &service.MFAEnrollmentCompleteResult{User: user, RememberMe: remember}, "user_session.login.success", false)
		}
	}
}
