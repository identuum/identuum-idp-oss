package handlers

// auth_lifecycle.go — HTTP routes for the OSS account-lifecycle
// surface ported from the monolith:
//
//   POST /api/v1/auth/password/reset-request
//   POST /api/v1/auth/password/reset
//   GET  /api/v1/auth/verify-email
//   POST /api/v1/auth/resend-verification
//   GET  /api/v1/auth/organizations/activate/:token
//   POST /api/v1/auth/organizations/activate
//   GET  /api/v1/auth/claim/validate
//   POST /api/v1/auth/claim
//
// Source-of-truth references for the wire contract:
//   identuum-idp/internal/handlers/handler_password_reset.go
//   identuum-idp/internal/handlers/verification.go
//   identuum-idp/internal/handlers/handler_activation.go
//   identuum-idp/internal/handlers/handler_claim.go
//
// Cookie / session safety invariants:
//
//   - NONE of these routes set Set-Cookie. Account lifecycle
//     ceremonies must complete BEFORE the operator initiates a
//     normal login (which is the only path that mints session
//     cookies). The handler explicitly does not call setAuthCookies.
//   - The password reset complete path revokes all sessions for the
//     affected user via UserSessionService (or the raw
//     SessionRepository seam). The handler does not see the session
//     cookies — revocation is handled inside the service.
//
// Secrets safety:
//
//   - Raw token values, reset links, activation links, claim URLs,
//     password plaintext, and email bodies are NEVER logged by this
//     file. Audit metadata carries only correlation handles (user
//     id, org id, claim id, target email).
//   - The 200 response on the anti-enumeration paths is uniform:
//     {success: true, message: "..."} for password-reset-request +
//     resend-verification, and {valid:false} / {success:false} for
//     the claim flow.

import (
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// AccountLifecycleHandlerDeps wires the four route families. Each
// service field gates registration of its corresponding routes.
type AccountLifecycleHandlerDeps struct {
	PasswordReset *service.PasswordResetService
	EmailVerify   *service.EmailVerificationService
	OrgActivation *service.OrganizationActivationService
	Claim         *service.ClaimService
	Audit         audit.Service

	// PasswordResetLimiter, when non-nil, is a per-IP rate-limit
	// middleware (built by the router from
	// RateLimitConfig.PasswordResetLimit) applied ONLY to the two
	// password-reset routes — the abuse-prone (flooding / enumeration)
	// surface. Nil (zero-value deps / tests) is a noop. Other lifecycle
	// routes are unaffected.
	PasswordResetLimiter gin.HandlerFunc
}

// RegisterAccountLifecycleRoutes mounts every route whose backing
// service is wired. Routes register independently — a deployment
// with only PasswordReset wired exposes only the password reset
// routes, etc.
func RegisterAccountLifecycleRoutes(router gin.IRouter, deps AccountLifecycleHandlerDeps) {
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.PasswordReset != nil {
		// Per-IP rate limit on the abuse-prone reset surface only. The
		// sub-group carries the limiter as group middleware; nil-safe
		// (noop when unconfigured). Registering on the sub-group keeps
		// the handler symbol visible to docgen at the call site.
		resetGroup := router.Group("")
		if deps.PasswordResetLimiter != nil {
			resetGroup.Use(deps.PasswordResetLimiter)
		}
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=POST
		// docgen:path=/api/v1/auth/password/reset-request
		// docgen:summary=Request a password reset link for the supplied email. Anti-enumeration — always 200 regardless of whether the email matches a user, plus a 100–300 ms random delay so timing cannot leak account existence.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. Raw reset token NEVER logged or echoed. SHA-256 hash persisted server-side. Email link uses the deployment's human-facing base URL.
		resetGroup.POST("/api/v1/auth/password/reset-request", HandleRequestPasswordReset(deps))
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=POST
		// docgen:path=/api/v1/auth/password/reset
		// docgen:summary=Complete a password reset using a one-time token. On success, all active sessions for the user are revoked.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=Single-use — token row is marked used BEFORE the password rewrite (burn-before-write). 400 invalid_reset_token / weak_password on rejection. No Set-Cookie. Raw token never logged.
		resetGroup.POST("/api/v1/auth/password/reset", HandleResetPassword(deps))
	}
	if deps.EmailVerify != nil {
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=GET
		// docgen:path=/api/v1/auth/verify-email
		// docgen:summary=Verify an email address via a one-time token. Idempotent — re-clicking the link after success returns 200. Single-use semantics enforced server-side.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. 400 invalid_token collapses every failure mode (bad / expired / consumed / unknown user). Raw token never logged.
		router.GET("/api/v1/auth/verify-email", HandleVerifyEmail(deps))
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=POST
		// docgen:path=/api/v1/auth/resend-verification
		// docgen:summary=Resend a verification email. Anti-enumeration — always 200 regardless of whether the email matches an unverified user.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. Banned / deleted / already-verified users are silently skipped. Raw token never echoed.
		router.POST("/api/v1/auth/resend-verification", HandleResendVerification(deps))
	}
	if deps.OrgActivation != nil {
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=GET
		// docgen:path=/api/v1/auth/organizations/activate/:token
		// docgen:summary=Validate an organization-activation token. Returns the org_admin's email + organization id so the UI can render the password-setup form.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=400 invalid_token on bad / expired / consumed token. 409 organization_already_active when the org has been flipped active through another path. Single-use semantics enforced on consume only — validate is a pre-flight that does NOT mutate state.
		router.GET("/api/v1/auth/organizations/activate/:token", HandleValidateActivationToken(deps))
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=POST
		// docgen:path=/api/v1/auth/organizations/activate
		// docgen:summary=Complete an organization activation. Sets the org_admin's password, marks the org Active, marks the org_admin's email verified, and consumes the activation token (single-use).
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=400 invalid_token / weak_password on rejection. 409 organization_already_active on idempotent re-submit. No Set-Cookie — operator must initiate a normal login afterwards. Activation does NOT generate a TOTP secret; MFA enrollment happens at first login via the existing /api/v1/auth/login/mfa/enroll/initiate flow.
		router.POST("/api/v1/auth/organizations/activate", HandleActivateOrganization(deps))
	}
	if deps.Claim != nil {
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=GET
		// docgen:path=/api/v1/auth/claim/validate
		// docgen:summary=Validate a claim token pre-flight (oracle-hardened — every failure mode returns 200 {valid:false}). When valid, returns the organization name and (for email-bound tokens) the bound target email.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. Raw token never logged. Wire response shape is uniform across every rejection mode.
		router.GET("/api/v1/auth/claim/validate", HandleValidateClaim(deps))
		// docgen:endpoint
		// docgen:surface=auth-lifecycle
		// docgen:method=POST
		// docgen:path=/api/v1/auth/claim
		// docgen:summary=Consume a claim token and mint the first org_admin for an empty organization. Oracle-hardened — every failure mode returns 200 with success:false. Bounded retry attempts on password-policy failures.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. After max attempts the token is burned and the response signals attempts_exhausted=true. Password violations return success:false + attempts_remaining counter. Single-use — successful consume deletes the claim row.
		router.POST("/api/v1/auth/claim", HandleConsumeClaim(deps))
	}
}

// ---------- POST /api/v1/auth/password/reset-request ----------

type passwordResetRequestBody struct {
	Email string `json:"email"`
}

type passwordResetGenericResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

const passwordResetRequestMessage = "If an account exists with this email, a password reset link has been sent."

// HandleRequestPasswordReset is the anti-enumeration entry point.
// Returns 200 + a fixed message regardless of whether the email
// matches a user; a 100–300 ms random delay is injected to defeat
// timing-based enumeration. Errors from the service layer are
// swallowed — the wire response is uniform.
func HandleRequestPasswordReset(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req passwordResetRequestBody
		if err := c.ShouldBindJSON(&req); err != nil {
			// Anti-enumeration: a malformed body must NOT be
			// distinguishable from a well-formed one with an
			// unknown email. Both branches return the same body.
			injectAntiEnumDelay()
			c.JSON(http.StatusOK, passwordResetGenericResponse{Success: true, Message: passwordResetRequestMessage})
			return
		}
		injectAntiEnumDelay()
		_ = deps.PasswordReset.RequestPasswordReset(c.Request.Context(), req.Email, c.ClientIP(), c.Request.UserAgent())
		c.JSON(http.StatusOK, passwordResetGenericResponse{Success: true, Message: passwordResetRequestMessage})
	}
}

// injectAntiEnumDelay sleeps for a random 100–300 ms window so the
// wall-clock response time cannot be used as an account-existence
// oracle. math/rand is fine here: we are NOT using the value as a
// security primitive (the security primitive is the constant-time
// repo lookup); the delay just dithers the response curve.
func injectAntiEnumDelay() {
	// rand.Intn(201) yields 0..200, so the sleep is 100..300 ms.
	time.Sleep(time.Millisecond * time.Duration(100+rand.Intn(201))) //nolint:gosec // anti-enumeration jitter, not a security primitive
}

// ---------- POST /api/v1/auth/password/reset ----------

type passwordResetCompleteBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type passwordResetSuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// HandleResetPassword completes the flow. Wire mapping:
//
//   - 200 on success.
//   - 400 invalid_reset_token on bad / expired / consumed token /
//     unknown user.
//   - 400 weak_password on policy violation.
//   - 500 internal_error on unexpected.
func HandleResetPassword(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req passwordResetCompleteBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
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
			c.JSON(http.StatusOK, passwordResetSuccessResponse{Success: true, Message: "Password has been successfully reset."})
		case errors.Is(err, service.ErrPasswordResetInvalidToken):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_reset_token"})
		case errors.Is(err, service.ErrPasswordResetWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		}
	}
}

// ---------- GET /api/v1/auth/verify-email ----------

type verifyEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// HandleVerifyEmail consumes a verification token from the query
// string. Returns 200 on success / 400 invalid_token otherwise.
// Idempotent — already-verified users see 200.
func HandleVerifyEmail(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Query("token")
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		err := deps.EmailVerify.VerifyEmail(c.Request.Context(), token, c.ClientIP(), c.Request.UserAgent())
		switch {
		case err == nil:
			c.JSON(http.StatusOK, verifyEmailResponse{Success: true, Message: "Email verified successfully"})
		case errors.Is(err, service.ErrEmailVerificationInvalidToken):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		}
	}
}

// ---------- POST /api/v1/auth/resend-verification ----------

type resendVerificationBody struct {
	Email string `json:"email"`
}

type resendVerificationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

const resendVerificationMessage = "If this email is registered, a verification link has been sent."

// HandleResendVerification is the anti-enumeration entry point.
// Always returns 200 with a fixed message. The service silently
// no-ops on unknown / already-verified emails.
func HandleResendVerification(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req resendVerificationBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusOK, resendVerificationResponse{Success: true, Message: resendVerificationMessage})
			return
		}
		_ = deps.EmailVerify.ResendVerification(c.Request.Context(), req.Email)
		c.JSON(http.StatusOK, resendVerificationResponse{Success: true, Message: resendVerificationMessage})
	}
}

// ---------- GET /api/v1/auth/organizations/activate/:token ----------

type activationValidationResponse struct {
	Success bool   `json:"success"`
	Email   string `json:"email"`
	OrgID   string `json:"org_id"`
}

// HandleValidateActivationToken is the GET pre-flight. Returns the
// org_admin's email + org id so the UI can render the password-
// setup form. Does NOT consume the token.
func HandleValidateActivationToken(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimSpace(c.Param("token"))
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		result, err := deps.OrgActivation.ValidateActivationToken(c.Request.Context(), token)
		switch {
		case err == nil && result != nil:
			c.JSON(http.StatusOK, activationValidationResponse{
				Success: true,
				Email:   result.Email,
				OrgID:   result.OrgID.String(),
			})
		case errors.Is(err, service.ErrOrganizationAlreadyActive):
			c.JSON(http.StatusConflict, gin.H{"error": "organization_already_active"})
		case errors.Is(err, service.ErrOrganizationActivationInvalidToken):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		}
	}
}

// ---------- POST /api/v1/auth/organizations/activate ----------

type activationCompleteBody struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type activationOrganizationView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Active  bool   `json:"active"`
	OrgSlug string `json:"org_slug"`
}

type activationCompleteResponse struct {
	Success      bool                       `json:"success"`
	Message      string                     `json:"message"`
	Organization activationOrganizationView `json:"organization"`
}

// HandleActivateOrganization consumes the activation token, sets
// the org_admin's password, and flips the org to Active.
func HandleActivateOrganization(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req activationCompleteBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		_, org, err := deps.OrgActivation.ConsumeActivationToken(c.Request.Context(), service.ConsumeActivationInput{
			Token:     req.Token,
			Password:  req.Password,
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		switch {
		case err == nil && org != nil:
			c.JSON(http.StatusOK, activationCompleteResponse{
				Success: true,
				Message: "Organization activated successfully. You can now login.",
				Organization: activationOrganizationView{
					ID:      org.ID.String(),
					Name:    org.Name,
					Domain:  org.Domain,
					Active:  org.Active,
					OrgSlug: org.OrgSlug,
				},
			})
		case errors.Is(err, service.ErrOrganizationAlreadyActive):
			c.JSON(http.StatusConflict, gin.H{"error": "organization_already_active"})
		case errors.Is(err, service.ErrOrganizationActivationWeakPassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": "weak_password"})
		case errors.Is(err, service.ErrOrganizationActivationInvalidToken):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_token"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		}
	}
}

// ---------- GET /api/v1/auth/claim/validate ----------

type validateClaimResponse struct {
	Valid            bool   `json:"valid"`
	OrganizationName string `json:"organization_name,omitempty"`
	TargetEmail      string `json:"target_email,omitempty"`
}

// HandleValidateClaim is the oracle-hardened pre-flight. Every
// failure mode returns 200 {valid:false}.
func HandleValidateClaim(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Query("token")
		result, err := deps.Claim.ValidateClaim(c.Request.Context(), token)
		if err != nil || result == nil {
			c.JSON(http.StatusOK, validateClaimResponse{Valid: false})
			return
		}
		c.JSON(http.StatusOK, validateClaimResponse{
			Valid:            result.Valid,
			OrganizationName: result.OrganizationName,
			TargetEmail:      result.TargetEmail,
		})
	}
}

// ---------- POST /api/v1/auth/claim ----------

type consumeClaimBody struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type consumeClaimResponse struct {
	Success           bool   `json:"success"`
	Message           string `json:"message,omitempty"`
	AttemptsRemaining *int   `json:"attempts_remaining,omitempty"`
	AttemptsExhausted bool   `json:"attempts_exhausted,omitempty"`
}

// HandleConsumeClaim consumes the supplied claim token. Failure
// modes collapse onto 200 {success:false}; password-policy and
// max-attempts failures carry the same envelope but with the
// attempts counters populated so the UI can render the right
// message.
func HandleConsumeClaim(deps AccountLifecycleHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req consumeClaimBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusOK, consumeClaimResponse{Success: false})
			return
		}
		result, err := deps.Claim.ConsumeClaim(c.Request.Context(), service.ConsumeClaimInput{
			Token:     req.Token,
			Email:     req.Email,
			Name:      req.Name,
			Password:  req.Password,
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		if err != nil || result == nil {
			c.JSON(http.StatusOK, consumeClaimResponse{Success: false})
			return
		}
		resp := consumeClaimResponse{Success: result.Success}
		switch {
		case result.AttemptsExhausted:
			resp.AttemptsExhausted = true
			resp.Message = "Maximum password attempts reached. Please contact your administrator for a new claim link."
		case result.Reason == "weak_password":
			n := result.AttemptsRemaining
			resp.AttemptsRemaining = &n
			resp.Message = "Password does not meet the required strength."
		}
		c.JSON(http.StatusOK, resp)
	}
}

// Compile-time silence-the-linter — keep `uuid` import for handler
// view types that round-trip UUIDs from the service layer.
var _ = uuid.Nil
