package handlers

// auth_mfa_self_enroll.go — FUNC-M1: account settings' "add an authenticator"
// for a signed-in user, on the paths and wire shape identuum-idp-ce serves
// and the console calls:
//
//   - POST /api/v1/mfa/setup/initiate {password} → 200 {secret, otpauth_url}
//   - POST /api/v1/mfa/setup/complete {code}     → 200 {recovery_codes}
//
// The pending enrolment is bound to the user on the server; the secret and
// the recovery codes are answered once, Cache-Control no-store, and never
// reach an audit row.

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type mfaSetupInitiateRequest struct {
	Password string `json:"password"`
}

type mfaSetupCompleteRequest struct {
	Code string `json:"code"`
}

// HandleMFASetupInitiate checks the current password and returns the
// candidate secret.
func HandleMFASetupInitiate(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		// An empty body or {} is "no password": the same 401 as a wrong one.
		var req mfaSetupInitiateRequest
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		start, err := deps.MFAEnrollment.InitiateSelf(c.Request.Context(), principal.UserID, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrLoginThrottled):
				respondLoginThrottled(c, err)
			case errors.Is(err, service.ErrMFASelfAlreadyEnrolled):
				c.JSON(http.StatusConflict, gin.H{"error": "mfa_already_enrolled"})
			case errors.Is(err, service.ErrMFASelfProofInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_proof"})
			case errors.Is(err, service.ErrMFAEnrollmentInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"secret": start.Secret, "otpauth_url": start.OtpauthURL})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         "user_session.mfa.self_enrollment_started",
			Outcome:        "success",
			SubjectID:      principal.UserID,
			SubjectType:    "user",
			OrganizationID: principal.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"user_id": principal.UserID.String()},
		})
	}
}

// HandleMFASetupComplete verifies the first code and enables MFA.
func HandleMFASetupComplete(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var req mfaSetupCompleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if strings.TrimSpace(req.Code) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "code_required"})
			return
		}
		codes, err := deps.MFAEnrollment.CompleteSelf(c.Request.Context(), principal.UserID, req.Code)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrMFASelfAlreadyEnrolled):
				c.JSON(http.StatusConflict, gin.H{"error": "mfa_already_enrolled"})
			case errors.Is(err, service.ErrMFASelfNotStarted):
				c.JSON(http.StatusBadRequest, gin.H{"error": "setup_not_started"})
			case errors.Is(err, service.ErrMFAEnrollmentInvalid):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         "user_session.mfa.self_enrolled",
			Outcome:        "success",
			SubjectID:      principal.UserID,
			SubjectType:    "user",
			OrganizationID: principal.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       map[string]any{"user_id": principal.UserID.String(), "recovery_codes_count": len(codes)},
		})
	}
}
