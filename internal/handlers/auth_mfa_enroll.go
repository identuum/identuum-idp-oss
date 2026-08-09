package handlers

// auth_mfa_enroll.go — OSS HTTP endpoints for the MFA enrolment +
// MFA verify pending-session flow added by slice
// agent-a-identuum-idp-oss-mfa-totp-enrolment-endpoints.
//
// Three routes wired here:
//
//   - POST /api/v1/auth/login/mfa/enroll/initiate
//   - POST /api/v1/auth/login/mfa/enroll/complete
//   - POST /api/v1/auth/login/mfa
//
// All three operate on a pending-MFA session_id minted by
// HandleLocalLogin when correct password authentication lands on a
// path that requires MFA but cannot yet issue a full session.
//
// Cookie + session safety invariants (these are the load-bearing
// reasons this file exists separate from auth_sessions.go):
//
//   - NO Set-Cookie is written before TOTP verification succeeds.
//     Both initiate and complete-on-failure paths short-circuit
//     before setAuthCookies. Only the success branch of complete +
//     verify (after MarkConsumed claims the pending row atomically)
//     calls setAuthCookies.
//
//   - The TOTP secret + recovery codes returned by /initiate are
//     shown ONCE to the operator. The response carries
//     Cache-Control: no-store so intermediaries (and the browser's
//     bfcache) do not retain them.
//
//   - The pending session_id is opaque and short-lived. Replay is
//     blocked by the repository's MarkConsumed UPDATE — atomic + DB-
//     side single-use enforcement.
//
//   - Errors collapse to opaque sentinels. The wire never
//     distinguishes consumed / expired / wrong-kind / wrong-code —
//     all return 401 invalid_request or invalid_code (depending on
//     the call site).

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// mintPendingMFAHandle is the small bridge HandleLocalLogin uses to
// attach a session_id to the mfa_required / mfa_enrollment_required
// 401 responses. Returns the empty string when (a) the service is
// not wired, (b) the partial LoginResult is nil or carries no user
// (defensive — the service contract guarantees a non-nil User on
// the two MFA sentinels, but the handler stays safe under future
// drift), (c) the pending-session creation itself errors out (we
// fail open — the response still carries the error sentinel, the
// UI shows "MFA required" without the inline session_id, and the
// user retries).
//
// We deliberately swallow the CreatePending error and audit it
// inline so the failure does not leak through the response body.
func mintPendingMFAHandle(c *gin.Context, deps AuthSessionsHandlerDeps, result *service.LoginResult, kind domain.MFAPendingKind, rememberMe bool) string {
	if deps.MFAEnrollment == nil {
		return ""
	}
	if result == nil || result.User == nil {
		return ""
	}
	row, err := deps.MFAEnrollment.CreatePending(c.Request.Context(), result.User, kind, rememberMe)
	if err != nil || row == nil {
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.mfa_pending_create_failure",
			Outcome:   "denied",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		return ""
	}
	return row.ID.String()
}

// ---------- /api/v1/auth/login/mfa/enroll/initiate ----------

type mfaEnrollInitiateRequest struct {
	SessionID string `json:"session_id"`
}

type mfaEnrollInitiateResponse struct {
	OtpauthURL    string   `json:"otpauth_url"`
	Secret        string   `json:"secret"`
	RecoveryCodes []string `json:"recovery_codes"`
	ExpiresAt     int64    `json:"expires_at"`
}

// HandleMFAEnrollInitiate populates the candidate TOTP secret +
// recovery codes on a pending enrol row and returns the otpauth
// URL + secret + codes for one-time client display.
//
// Wire mappings:
//
//   - 200 + mfaEnrollInitiateResponse on success. Cache-Control:
//     no-store is set so intermediaries do not retain the secret.
//   - 400 {"error":"invalid_request"} when session_id is missing,
//     malformed, or not a valid UUID.
//   - 401 {"error":"invalid_request"} when the pending row does not
//     exist OR is expired OR is already consumed OR is the wrong
//     kind. The wire NEVER distinguishes these cases.
//   - 500 only on persistence failures the service cannot map to a
//     sentinel (rare).
//
// NO cookies are set on any path.
func HandleMFAEnrollInitiate(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req mfaEnrollInitiateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		id, err := uuid.Parse(req.SessionID)
		if err != nil || id == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		out, err := deps.MFAEnrollment.Initiate(c.Request.Context(), id)
		if err != nil {
			if errors.Is(err, service.ErrMFAEnrollmentNotFound) ||
				errors.Is(err, service.ErrMFAEnrollmentInvalid) ||
				errors.Is(err, service.ErrMFAEnrollmentExpired) ||
				errors.Is(err, service.ErrMFAEnrollmentAlreadyConsumed) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_request"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		// Cache-Control: no-store ensures the secret material is
		// not retained by intermediaries or browser bfcache.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.JSON(http.StatusOK, mfaEnrollInitiateResponse{
			OtpauthURL:    out.OtpauthURL,
			Secret:        out.Secret,
			RecoveryCodes: out.RecoveryCodes,
			ExpiresAt:     out.ExpiresAt.Unix(),
		})
	}
}

// ---------- /api/v1/auth/login/mfa/enroll/complete ----------

type mfaEnrollCompleteRequest struct {
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
}

// HandleMFAEnrollComplete verifies the supplied TOTP code against
// the candidate secret stored by /initiate. On success the user's
// mfa_enabled flag flips to true, the candidate secret + recovery
// codes persist onto the user row, the pending row is consumed,
// and the full login completes (CreateUserSession + IssueForSession
// + setAuthCookies) — the wire response shape matches a normal
// /api/v1/auth/login success.
//
// Wire mappings:
//
//   - 200 + localLoginResponse + Set-Cookie access_token (+
//     refresh_token when remember_me=true on the original /login)
//     on success.
//   - 400 invalid_request when session_id is malformed.
//   - 401 invalid_code on any failure (wrong code, expired pending,
//     consumed pending, wrong-kind pending, missing pending).
//
// NO cookies set on the failure paths.
func HandleMFAEnrollComplete(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req mfaEnrollCompleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		id, err := uuid.Parse(req.SessionID)
		if err != nil || id == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if req.Code == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code"})
			return
		}
		out, err := deps.MFAEnrollment.Complete(c.Request.Context(), id, req.Code)
		if err != nil {
			emitPendingFailure(c, deps, err, "user_session.login.mfa_enroll_complete_failure")
			return
		}
		completeMFALogin(c, deps, out, "user_session.login.mfa_enrolled")
	}
}

// ---------- /api/v1/auth/login/mfa ----------

type mfaVerifyRequest struct {
	SessionID string `json:"session_id"`
	Code      string `json:"code"`
}

// HandleMFAVerifyLogin completes a two-step login for an already-
// enrolled user. The pending row (kind=verify) is consumed only on
// successful TOTP verification against the user's persisted
// MFASecret; full session issuance + cookies happen on the same
// success path that the normal /login uses.
//
// Wire mappings mirror HandleMFAEnrollComplete.
func HandleMFAVerifyLogin(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req mfaVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		id, err := uuid.Parse(req.SessionID)
		if err != nil || id == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if req.Code == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code"})
			return
		}
		out, err := deps.MFAEnrollment.VerifyAndConsume(c.Request.Context(), id, req.Code)
		if err != nil {
			emitPendingFailure(c, deps, err, "user_session.login.mfa_verify_failure")
			return
		}
		completeMFALogin(c, deps, out, "user_session.login.mfa_verified")
	}
}

// ---------- /api/v1/me/mfa/recovery-codes/regenerate ----------

// mfaRecoveryCodesRegenerateResponse is the shape the self-service
// regenerate route returns. Codes are shown ONCE to the operator
// (the only place the new list exists in plaintext is this
// response body); the count is included so the UI can render the
// "show all N new codes" affordance without re-counting.
type mfaRecoveryCodesRegenerateResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
	Count         int      `json:"count"`
}

// HandleMFARecoveryCodesRegenerate replaces the authenticated
// user's MFA recovery codes with a fresh list and returns the new
// codes ONCE. The request body is ignored entirely — the only
// authority gate is the bound principal from
// mw.PrincipalFromContext, so a user can ONLY regenerate their
// OWN codes (cross-user calls are structurally impossible on this
// surface).
//
// MFAEnabled and MFASecret are NOT modified by this handler. The
// caller's existing TOTP enrolment continues to work; only the
// recovery codes are rotated.
//
// Wire mappings:
//
//   - 200 + mfaRecoveryCodesRegenerateResponse on success.
//     Cache-Control: no-store + Pragma: no-cache so intermediaries
//     and the browser bfcache do not retain the fresh codes.
//   - 400 {"error":"mfa_not_enrolled"} when the principal has not
//     enrolled MFA yet (MFAEnabled=false on the user row).
//   - 401 {"error":"unauthorized"} when the route runs without an
//     authenticated principal (defence in depth — the route
//     middleware already enforces this).
//   - 500 {"error":"internal_error"} for persistence or generator
//     failures the service cannot map to a sentinel (rare).
//
// Audit: emits "user_session.mfa.recovery_codes_regenerated" with
// user_id + the COUNT of new codes. The raw codes are NEVER in
// the audit metadata, the response logger, or any error string.
func HandleMFARecoveryCodesRegenerate(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		codes, err := deps.MFAEnrollment.RegenerateRecoveryCodes(c.Request.Context(), principal.UserID)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrMFANotEnrolled):
				c.JSON(http.StatusBadRequest, gin.H{"error": "mfa_not_enrolled"})
			case errors.Is(err, service.ErrMFAEnrollmentInvalid):
				// Stale principal / banned / deleted / programmer-
				// error path: collapse to the same opaque 401 the
				// rest of the surface uses so a probe can't tell
				// "deleted" from "banned" from "missing".
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		// Cache-Control + Pragma mirror the /enroll/initiate
		// response posture — the secret material in the body is
		// one-shot.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.JSON(http.StatusOK, mfaRecoveryCodesRegenerateResponse{
			RecoveryCodes: codes,
			Count:         len(codes),
		})
		// Audit event: count only, never the codes. The action
		// string is a fresh suffix on the existing
		// "user_session.mfa.*" namespace so dashboard filters that
		// already match `user_session.mfa.*` pick it up.
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.mfa.recovery_codes_regenerated",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"user_id":              principal.UserID.String(),
				"recovery_codes_count": len(codes),
			},
		})
	}
}

// ---------- /api/v1/me/mfa/status ----------

// mfaStatusResponse is the safe self-service projection returned
// by the status route. Field names match the brief verbatim
// (mfa_enabled / recovery_codes_remaining_count / totp_enrolled)
// so a UI built against the documented contract does not need to
// translate.
type mfaStatusResponse struct {
	MFAEnabled                  bool `json:"mfa_enabled"`
	RecoveryCodesRemainingCount int  `json:"recovery_codes_remaining_count"`
	TOTPEnrolled                bool `json:"totp_enrolled"`
}

// HandleMFAStatus returns the authenticated user's own MFA status.
// The request body and query string are ignored entirely — the
// only authority gate is the bound principal from
// mw.PrincipalFromContext, so a user can ONLY read THEIR OWN
// status (cross-user reads are structurally impossible: there is
// no user_id parameter on the wire).
//
// Wire mappings:
//
//   - 200 + mfaStatusResponse on success. Cache-Control: no-store +
//     Pragma: no-cache so the identity-state hints (enrolled?
//     codes-remaining count?) are not retained by intermediaries
//     or the browser bfcache.
//   - 401 {"error":"unauthorized"} when the route runs without an
//     authenticated principal OR when the bound principal points at
//     a stale / banned / soft-deleted user. The opaque envelope
//     mirrors HandleMFARecoveryCodesRegenerate so a probe cannot
//     tell "deleted" from "banned" from "missing".
//   - 500 {"error":"internal_error"} for unexpected service
//     failures.
//
// The response NEVER carries MFASecret, otpauth URL, recovery
// code values, password hash, tokens, or session material. The
// only fields that exist in the response are the three documented
// projections.
func HandleMFAStatus(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		status, err := deps.MFAEnrollment.GetMFAStatus(c.Request.Context(), principal.UserID)
		if err != nil {
			if errors.Is(err, service.ErrMFAEnrollmentInvalid) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		// Cache-Control + Pragma match the rest of the /me MFA
		// surface's posture — identity state is not cacheable.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.JSON(http.StatusOK, mfaStatusResponse{
			MFAEnabled:                  status.MFAEnabled,
			RecoveryCodesRemainingCount: status.RecoveryCodesRemaining,
			TOTPEnrolled:                status.TOTPEnrolled,
		})
	}
}

// ---------- shared helpers ----------

// emitPendingFailure collapses every pending-MFA sentinel to the
// same opaque 401 with invalid_code. We audit the failure shape
// internally (for ops) but do NOT echo it on the wire.
func emitPendingFailure(c *gin.Context, deps AuthSessionsHandlerDeps, err error, auditAction string) {
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    auditAction,
		Outcome:   "denied",
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if errors.Is(err, service.ErrMFAEnrollmentNotFound) ||
		errors.Is(err, service.ErrMFAEnrollmentInvalid) ||
		errors.Is(err, service.ErrMFAEnrollmentExpired) ||
		errors.Is(err, service.ErrMFAEnrollmentAlreadyConsumed) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_code"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
}

// completeMFALogin issues the full session + access/refresh tokens
// + Set-Cookie + 200 response that a normal /api/v1/auth/login
// success returns. Used by both HandleMFAEnrollComplete and
// HandleMFAVerifyLogin so the post-MFA wire shape is identical
// to the post-password wire shape (single contract for the UI).
func completeMFALogin(c *gin.Context, deps AuthSessionsHandlerDeps, out *service.MFAEnrollmentCompleteResult, auditAction string) {
	if deps.UserSession == nil || out == nil || out.User == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	var ipPtr, uaPtr *string
	if ip != "" {
		ipPtr = &ip
	}
	if ua != "" {
		uaPtr = &ua
	}
	maxSessions := 0
	if out.User.OrgMaxSessionsPerUser != nil {
		maxSessions = *out.User.OrgMaxSessionsPerUser
	}
	issued, err := deps.UserSession.CreateUserSession(c.Request.Context(), service.CreateUserSessionInput{
		UserID:             out.User.ID,
		IPAddress:          ipPtr,
		UserAgent:          uaPtr,
		RememberMe:         out.RememberMe,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     out.User.OrganizationID,
		Role:               string(out.User.Role),
	})
	if err != nil || issued == nil || issued.Session == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:    auditAction,
		Outcome:   "success",
		IPAddress: ip,
		UserAgent: ua,
		Metadata: map[string]any{
			"user_id":    out.User.ID.String(),
			"session_id": issued.Session.ID.String(),
		},
	})
	if out.RecoveryCodeUsed {
		// Recovery-code consumption is a distinct security-relevant
		// event from a regular TOTP verification. The raw code is
		// NEVER included — only the remaining count, which lets
		// operators alert on a user running their recovery list
		// down.
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.mfa_recovery_code_consumed",
			Outcome:   "success",
			IPAddress: ip,
			UserAgent: ua,
			Metadata: map[string]any{
				"user_id":                        out.User.ID.String(),
				"session_id":                     issued.Session.ID.String(),
				"remaining_recovery_codes_count": out.RemainingRecoveryCodes,
			},
		})
	}
	resp := localLoginResponse{
		UserID:       out.User.ID.String(),
		SessionID:    issued.Session.ID.String(),
		RefreshToken: issued.RefreshToken,
		ExpiresAt:    issued.Session.ExpiresAt.Unix(),
		Role:         string(out.User.Role),
		Email:        out.User.Email,
	}
	if deps.UserToken != nil {
		access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), out.User, issued.Session)
		if accessErr == nil && access != nil {
			resp.AccessToken = access.AccessToken
			resp.TokenType = access.TokenType
			resp.ExpiresIn = access.ExpiresIn
		}
	}
	setAuthCookies(c, resp.AccessToken, resp.RefreshToken, out.RememberMe)
	c.JSON(http.StatusOK, resp)
}
