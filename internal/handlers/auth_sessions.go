package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// UserByIDLookup is the narrow seam the auth-session handlers
// consume to resolve a session's user_id back to a *domain.User
// during the refresh flow. *PgxUserRepository satisfies it via
// GetByID.
type UserByIDLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// AuthSessionsHandlerDeps wires the local-login / session-refresh
// / logout / validate routes. LocalLogin is REQUIRED for the login
// route; UserSession is REQUIRED for refresh + logout. The
// /api/v1/validate route registers only when TokenVerifier,
// SessionLookup, and UserLookup are ALL non-nil. Routes register
// conditionally on the deps.
type AuthSessionsHandlerDeps struct {
	LocalLogin    *service.LocalLoginService
	UserSession   *service.UserSessionService
	UserToken     *service.UserTokenService
	UserLookup    UserByIDLookup
	SessionLookup SessionByIDLookup
	TokenVerifier ValidateTokenVerifier
	// MFAEnrollment, when wired, lets HandleLocalLogin attach a
	// pending-MFA session_id to the mfa_enrollment_required / mfa_required
	// 401 responses AND lets the new /api/v1/auth/login/mfa/enroll/initiate +
	// /api/v1/auth/login/mfa/enroll/complete + /api/v1/auth/login/mfa
	// routes register. When nil, the legacy single-step contract
	// stays in force (UI must re-submit /login with TOTPCode in the
	// request body for enrolled users; admin enrolment is blocked
	// at the policy gate with no pending handle).
	MFAEnrollment *service.MFAEnrollmentService
	// SessionRevoker is the best-effort seam consulted by the
	// self-service MFA disable handler so a user whose MFA is
	// turned off cannot keep authenticating through a pre-existing
	// session. Defaults to service.NoopSessionRevoker when nil so
	// deployments that have not wired a session store keep the
	// /me/mfa surface mountable. Warn-and-continue contract.
	SessionRevoker service.SessionRevoker
	// RefreshTokenRevoker is the parallel best-effort seam for
	// OAuth refresh tokens. Same warn-and-continue contract.
	RefreshTokenRevoker service.UserRefreshTokenRevoker
	Audit               audit.Service
}

// ValidateTokenVerifier is the narrow seam GET /api/v1/validate
// consumes. *auth.RepositoryVerifier (and any other
// mw.TokenVerifier-shaped value) satisfies it. We do NOT import
// internal/mw here because mw imports handlers transitively in the
// existing wiring; the local interface keeps the auth-sessions
// handler self-contained.
type ValidateTokenVerifier interface {
	VerifyBearerToken(ctx context.Context, token string) (*domain.Principal, error)
}

// RegisterAuthSessionRoutes mounts:
//
//	POST /api/v1/auth/login
//	POST /api/v1/auth/session/refresh
//	POST /api/v1/auth/logout
//	GET  /api/v1/validate
//
// onto router. Each route mounts only when its required dep is
// non-nil. The login route now also sets `access_token` (and
// `refresh_token` when one is minted) HttpOnly cookies on success —
// the JSON body remains for callers that want to read the token
// directly, but the browser-side identuum-ui consumes the cookies.
func RegisterAuthSessionRoutes(router gin.IRouter, deps AuthSessionsHandlerDeps) {
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.SessionRevoker == nil {
		deps.SessionRevoker = service.NoopSessionRevoker{}
	}
	if deps.RefreshTokenRevoker == nil {
		deps.RefreshTokenRevoker = service.NoopRefreshTokenRevoker{}
	}
	if deps.LocalLogin != nil {
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login
		// docgen:summary=Local email/password login. Verifies credentials + optional TOTP and returns a session/user-token; password is never echoed in the response or any audit metadata.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=Anonymous endpoint — the request body carries the credentials; the handler validates them and rate-limits brute-force attempts. Successful response also sets access_token (and refresh_token when minted) HttpOnly Lax cookies for browser consumption.
		router.POST("/api/v1/auth/login", HandleLocalLogin(deps))
	}
	if deps.UserSession != nil {
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/session/refresh
		// docgen:summary=Refresh the authenticated principal's session (rotates the session token; old token is invalidated server-side).
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Caller must present an existing valid session; the rotated token is returned ONCE in the response body.
		router.POST("/api/v1/auth/session/refresh", HandleSessionRefresh(deps))

		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/logout
		// docgen:summary=Log out the authenticated principal's session (idempotent — unknown / already-revoked sessions return 204).
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:status=204
		router.POST("/api/v1/auth/logout", HandleLogout(deps))

		// Back-compat alias for the pre-split logout path. The UI logout
		// server-route (identuum-ui src/app/api/auth/logout/route.ts) and the
		// pre-split ancestor (identuum-idp/auth-service: protected.POST("/logout"))
		// call POST /api/v1/logout; the OSS split moved the route to
		// /api/v1/auth/logout without updating the caller, so the UI logout 404'd
		// and never reached HandleLogout — leaving the session usable post-logout.
		// Registering the original path as an alias to the SAME handler is the
		// minimal wiring required for logout to actually revoke the session
		// server-side. Same handler, same (no) auth gate as the canonical path.
		router.POST("/api/v1/logout", HandleLogout(deps))
	}
	if deps.MFAEnrollment != nil && deps.UserSession != nil {
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login/mfa/enroll/initiate
		// docgen:summary=Pending-MFA enrolment initiate. Given a session_id minted by /api/v1/auth/login on the mfa_enrollment_required path, generates a fresh TOTP candidate secret + recovery codes and returns the otpauth URL for one-time client QR display.
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Response carries Cache-Control no-store. Secret + recovery codes are shown ONCE; the server never returns them again. No Set-Cookie is written on any path. 401 invalid_request collapses all failure modes (consumed / expired / wrong-kind / missing).
		router.POST("/api/v1/auth/login/mfa/enroll/initiate", HandleMFAEnrollInitiate(deps))
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login/mfa/enroll/complete
		// docgen:summary=Pending-MFA enrolment complete. Verifies the supplied TOTP code against the candidate secret from /initiate, persists mfa_enabled=true + mfa_secret + mfa_recovery_codes onto the user row, marks the pending row consumed, and completes the login by issuing the full session + Set-Cookie access_token (and refresh_token when remember_me was set on the original /login).
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Cookies are set ONLY after TOTP verification succeeds AND the pending row's MarkConsumed UPDATE atomically claims it. 401 invalid_code on any failure (wrong code / expired / replay attempt).
		router.POST("/api/v1/auth/login/mfa/enroll/complete", HandleMFAEnrollComplete(deps))
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login/mfa
		// docgen:summary=Two-step MFA verification. For users already enrolled in TOTP; consumes the pending verify-kind session_id from /api/v1/auth/login on the mfa_required path, verifies the TOTP code against the user's persisted MFASecret, and completes the login by issuing the full session + Set-Cookie.
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Cookies are set ONLY after TOTP verification succeeds AND the pending row's MarkConsumed UPDATE atomically claims it. 401 invalid_code on any failure.
		router.POST("/api/v1/auth/login/mfa", HandleMFAVerifyLogin(deps))
	}
	if deps.MFAEnrollment != nil {
		// Self-service MFA recovery-code regeneration. Authenticated
		// principal regenerates their OWN codes only; the route's
		// authority gate is mw.RequireAuthenticated, and the
		// handler reads mw.PrincipalFromContext to derive the
		// user_id — there is no `user_id` parameter on the wire,
		// so cross-user calls are structurally impossible. The
		// route mounts independently of UserSession because it
		// neither rotates the session nor sets any cookies.
		recovery := router.Group("/api/v1/me/mfa/recovery-codes")
		recovery.Use(mw.RequireAuthenticated())
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/me/mfa/recovery-codes/regenerate
		// docgen:summary=Self-service MFA recovery-code regeneration. Replaces the authenticated user's stored recovery codes with a fresh list of the same length+count as enrolment and returns the new codes EXACTLY ONCE. MFAEnabled and MFASecret are not modified; the user's existing TOTP enrolment continues to work.
		// docgen:tier=oss
		// docgen:auth=authenticated
		// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. 400 mfa_not_enrolled when MFAEnabled=false on the principal. 401 unauthorized for stale / missing principals. The raw recovery codes never appear in audit metadata, logs, or error envelopes — they are returned ONCE in the response body.
		recovery.POST("/regenerate", HandleMFARecoveryCodesRegenerate(deps))

		// Self-service MFA status read. Same authority shape as the
		// regenerate route: mw.RequireAuthenticated gates entry and
		// mw.PrincipalFromContext supplies the user_id; no
		// user_id parameter is on the wire so cross-user reads are
		// structurally impossible. The response is the safe
		// projection (mfa_enabled + recovery_codes_remaining_count
		// + totp_enrolled) and NEVER carries the MFA secret,
		// otpauth URL, recovery code values, password hash,
		// tokens, or session material.
		status := router.Group("/api/v1/me/mfa")
		status.Use(mw.RequireAuthenticated())
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=GET
		// docgen:path=/api/v1/me/mfa/status
		// docgen:summary=Self-service MFA status read. Returns the safe projection of the authenticated user's MFA configuration: mfa_enabled, recovery_codes_remaining_count, totp_enrolled. Never returns MFA secret, otpauth URL, recovery code values, password hash, tokens, or session material.
		// docgen:tier=oss
		// docgen:auth=authenticated
		// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache so identity-state hints are not retained by intermediaries or browser bfcache. 401 unauthorized when the bound principal is missing, stale, banned, or soft-deleted (collapsed to the same opaque envelope used by /api/v1/me/mfa/recovery-codes/regenerate).
		status.GET("/status", HandleMFAStatus(deps))

		// Self-service MFA disable. Same authority shape as the
		// other /me/mfa surfaces: mw.RequireAuthenticated gates
		// entry and mw.PrincipalFromContext supplies the user_id;
		// no user_id parameter is on the wire so cross-user calls
		// are structurally impossible. The handler requires a
		// fresh TOTP code, one valid recovery code, OR the
		// authenticated user's current password in the request body
		// and BLOCKS the disable when the principal's role or
		// organization policy requires MFA.
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/me/mfa/disable
		// docgen:summary=Self-service MFA disable. Verifies a fresh TOTP code, one valid recovery code, OR the authenticated user's current password, then clears mfa_enabled / mfa_secret / mfa_recovery_codes on the authenticated user's row. Blocked when the principal is site_admin, org_admin, or in an organization whose mfa_policy is "required". On success the user's existing sessions and OAuth refresh tokens are revoked best-effort.
		// docgen:tier=oss
		// docgen:auth=authenticated
		// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. 204 No Content on success. 400 invalid_request when the request body is malformed. 400 mfa_not_enrolled when MFAEnabled=false on the principal. 401 invalid_code when the supplied code matches neither the TOTP secret nor any recovery code, or when the current-password proof fails (opaque — the wire NEVER distinguishes wrong-TOTP from wrong-recovery from wrong-password). When both code and password are supplied, non-empty code is authoritative: a valid code succeeds even with a wrong password, and a wrong non-empty code fails without password fallback. 401 unauthorized for stale / missing / banned / soft-deleted principals (same opaque envelope used by the other /me/mfa surfaces). 403 mfa_required_by_policy when role or org policy forces MFA. The supplied code, password, MFASecret, recovery codes, session IDs, access tokens, refresh tokens, token hashes, and password hash NEVER appear in the response body, audit metadata, headers, or any error envelope.
		// docgen:status=204
		status.POST("/disable", HandleMFADisableSelf(deps))
	}
	if deps.UserLookup != nil {
		sessions := router.Group("/api/v1/me/sessions")
		sessions.Use(mw.RequireAuthenticated())
		if deps.UserSession != nil {
			// docgen:endpoint
			// docgen:surface=auth
			// docgen:method=GET
			// docgen:path=/api/v1/me/sessions
			// docgen:summary=Self-service active session/device list. Returns safe metadata for the authenticated user's own active sessions only.
			// docgen:tier=oss
			// docgen:auth=authenticated
			// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. The route accepts no request body and no user_id query/path parameter; user identity is derived only from the authenticated principal. 401 unauthorized for stale / missing / banned / soft-deleted principals. Response entries include created_at, last_seen_at when known, expires_at, user_agent when stored, ip_address when stored, and current_session when the authenticated principal carries a session id. The response never includes session IDs, cookies, access tokens, refresh tokens, token selectors, validator hashes, token hashes, password hashes, MFA secrets, recovery codes, or credential material.
			sessions.GET("", HandleListOwnActiveSessions(deps))
			if deps.SessionLookup != nil {
				// docgen:endpoint
				// docgen:surface=auth
				// docgen:method=POST
				// docgen:path=/api/v1/me/sessions/revoke-current
				// docgen:summary=Self-service revoke current session/device. Revokes only the authenticated user's current browser session derived from the bound principal.
				// docgen:tier=oss
				// docgen:auth=authenticated
				// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. 204 No Content on success. The route accepts no request body and no query/path parameters; current user and session identity are derived only from the authenticated principal and verified against the session repository before revocation. 401 unauthorized for missing current session identity, stale / missing / banned / soft-deleted principals, or a principal whose session row is missing, revoked, expired, or owned by another user. The response and audit metadata never include session IDs, cookies, access tokens, refresh tokens, token hashes, password hashes, MFA secrets, recovery codes, or credential material.
				// docgen:status=204
				sessions.POST("/revoke-current", HandleRevokeCurrentOwnSession(deps))
				// docgen:endpoint
				// docgen:surface=auth
				// docgen:method=POST
				// docgen:path=/api/v1/me/sessions/revoke-others
				// docgen:summary=Self-service revoke other sessions/devices. Revokes every active browser session for the authenticated user except the current session derived from the bound principal.
				// docgen:tier=oss
				// docgen:auth=authenticated
				// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. 204 No Content on success. The route accepts no request body and no query/path parameters; current user and session identity are derived only from the authenticated principal and verified against the session repository before revoking other active sessions. 401 unauthorized for missing current session identity, stale / missing / banned / soft-deleted principals, or a principal whose current session row is missing, revoked, expired, or owned by another user. The current session is preserved. The response and audit metadata never include session IDs, cookies, access tokens, refresh tokens, token hashes, password hashes, MFA secrets, recovery codes, or credential material.
				// docgen:status=204
				sessions.POST("/revoke-others", HandleRevokeOtherOwnSessions(deps))
			}
		}
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=POST
		// docgen:path=/api/v1/me/sessions/revoke-all
		// docgen:summary=Self-service revoke all sessions/devices. Revokes every active browser session and OAuth refresh token for the authenticated user only.
		// docgen:tier=oss
		// docgen:auth=authenticated
		// docgen:notes=Response carries Cache-Control no-store + Pragma no-cache. 204 No Content on success. The route accepts no request body and no user_id query/path parameter; user identity is derived only from the authenticated principal. 401 unauthorized for stale / missing / banned / soft-deleted principals. Session and refresh-token revoker failures are best-effort and do not change the 204 response. The response and audit metadata never include session IDs, cookies, access tokens, refresh tokens, token hashes, password hashes, or secrets.
		// docgen:status=204
		sessions.POST("/revoke-all", HandleRevokeAllOwnSessions(deps))
	}
	if deps.TokenVerifier != nil && deps.SessionLookup != nil && deps.UserLookup != nil {
		// docgen:endpoint
		// docgen:surface=auth
		// docgen:method=GET
		// docgen:path=/api/v1/validate
		// docgen:summary=Validate the caller's session (access_token cookie or Authorization: Bearer). Returns the authenticated user + role for UI session-guard consumption. 401 on any verification failure.
		// docgen:tier=oss
		// docgen:auth=session|bearer
		// docgen:notes=Reads access_token cookie first; falls back to Authorization: Bearer. Verifies JWT signature + claims via the OSS RepositoryVerifier, confirms the session exists + is not revoked + is not expired, and confirms the user exists + is not banned + is not deleted. Token values are never echoed in the response.
		router.GET("/api/v1/validate", HandleValidateSession(deps))
	}
}

// ---------- Login ----------

type localLoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPCode   string `json:"totp_code"`
	RememberMe bool   `json:"remember_me"`
}

type localLoginResponse struct {
	UserID       string `json:"user_id"`
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	// Role surfaces the authenticated user's role on the login
	// response so identuum-ui's `login()` helper can route the
	// browser to the correct landing page (site_admin → /site-admin,
	// org_admin → /org-admin, org_user → /dashboard). Pre-this-slice
	// the field was absent and the UI fell back to org_user, which
	// caused site_admin operators to be routed to /dashboard and then
	// to /login?reason=session_expired by the role guard.
	Role string `json:"role,omitempty"`
	// Email is included to give the UI a stable handle for client-
	// side display without an extra /validate round-trip when the
	// login response is the first authenticated payload.
	Email string `json:"email,omitempty"`
}

// HandleLocalLogin runs the email/password (+ optional TOTP)
// login flow. Wire mappings:
//
//   - 200 + localLoginResponse on success (refresh_token shown
//     EXACTLY ONCE).
//   - 401 {"error":"invalid_credentials"} for bad password /
//     unknown user / banned / deleted / ambiguous email / MFA
//     code mismatch.
//   - 401 {"error":"mfa_required"} when the user has MFA
//     enabled and did not supply a TOTP code.
//   - 401 {"error":"mfa_enrollment_required"} when MFA is
//     required by policy (role == site_admin / org_admin OR the
//     user's organization has mfa_policy=required) and the user
//     has NOT enrolled a TOTP secret. NO access_token cookie,
//     refresh_token cookie, or session is created on this path
//     — the caller must complete TOTP enrolment before the next
//     login attempt.
//   - 401 {"error":"account_unverified"} when the email has not
//     been verified.
//   - 500 only on persistence errors that bypass the sentinel
//     set.
//
// Access tokens are NOT issued by this slice — the future
// authorization-code grant slice will mint a JWT for the human
// user. The wire shape is forward-compatible (callers ignore
// any extra fields).
func HandleLocalLogin(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req localLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
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
		result, err := deps.LocalLogin.Login(c.Request.Context(), service.LoginInput{
			Email:      req.Email,
			Password:   req.Password,
			TOTPCode:   req.TOTPCode,
			RememberMe: req.RememberMe,
			IPAddress:  ipPtr,
			UserAgent:  uaPtr,
		})
		if err != nil {
			emitLoginError(c, deps, err, result, req.RememberMe)
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.success",
			Outcome:   "success",
			IPAddress: ip,
			UserAgent: ua,
			Metadata: map[string]any{
				"user_id":    result.UserID,
				"session_id": result.Session.ID.String(),
			},
		})
		resp := localLoginResponse{
			UserID:       result.UserID,
			SessionID:    result.Session.ID.String(),
			RefreshToken: result.RefreshToken,
			ExpiresAt:    result.Session.ExpiresAt.Unix(),
		}
		if result.User != nil {
			resp.Role = string(result.User.Role)
			resp.Email = result.User.Email
		}
		// Optional access-token minting. When UserTokenService is
		// wired, the login response includes a signed JWT plus the
		// standard RFC 6749 §5.1 token_type / expires_in pair so
		// the caller can treat the response as both a session
		// bootstrap AND an access-token bootstrap.
		if deps.UserToken != nil && result.User != nil {
			access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), result.User, result.Session)
			if accessErr == nil {
				resp.AccessToken = access.AccessToken
				resp.TokenType = access.TokenType
				resp.ExpiresIn = access.ExpiresIn
			}
			// On error: the wire response simply omits the
			// access-token fields. The login itself succeeded;
			// callers can rotate via /session/refresh to retry.
		}
		// Set browser cookies for identuum-ui consumption. Match the
		// monolith's contract: access_token + refresh_token, HttpOnly,
		// SameSite=Lax, Path=/, localhost-aware Secure. Tokens that
		// were not minted (e.g. UserTokenService nil) are passed as
		// empty strings — setAuthCookies skips Set-Cookie writes for
		// empty values, so the response stays clean.
		setAuthCookies(c, resp.AccessToken, resp.RefreshToken, req.RememberMe)
		c.JSON(http.StatusOK, resp)
	}
}

func emitLoginError(c *gin.Context, deps AuthSessionsHandlerDeps, err error, result *service.LoginResult, rememberMe bool) {
	switch {
	case errors.Is(err, service.ErrLoginMFARequired):
		body := gin.H{"error": "mfa_required", "mfa_required": true, "mfa_enrollment_required": false}
		sessionID := mintPendingMFAHandle(c, deps, result, domain.MFAPendingKindVerify, rememberMe)
		if sessionID != "" {
			body["session_id"] = sessionID
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.mfa_required",
			Outcome:   "denied",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		c.JSON(http.StatusUnauthorized, body)
	case errors.Is(err, service.ErrLoginMFAEnrollmentRequired):
		// Policy-required MFA but the user has not yet enrolled a
		// TOTP secret. The handler MUST NOT issue access/refresh
		// tokens, MUST NOT set cookies, and MUST NOT create a
		// session. The wire response carries no token material;
		// the caller (UI) drives the user through TOTP enrolment
		// via /api/v1/auth/login/mfa/enroll/initiate +
		// /api/v1/auth/login/mfa/enroll/complete using the
		// returned session_id.
		body := gin.H{"error": "mfa_enrollment_required", "mfa_required": true, "mfa_enrollment_required": true}
		sessionID := mintPendingMFAHandle(c, deps, result, domain.MFAPendingKindEnroll, rememberMe)
		if sessionID != "" {
			body["session_id"] = sessionID
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.mfa_enrollment_required",
			Outcome:   "denied",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		c.JSON(http.StatusUnauthorized, body)
	case errors.Is(err, service.ErrLoginAccountUnverified):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account_unverified"})
	case errors.Is(err, service.ErrLoginInvalidCredentials):
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.failure",
			Outcome:   "denied",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
	case errors.Is(err, service.ErrLoginRiskBackendUnavailable):
		// Fail-CLOSED: the brute-force lockout backend was unreachable,
		// so the login is refused rather than proceeding unguarded. 503
		// reveals ONLY backend state — this path is reached independently
		// of whether the account exists (the password gate runs Check
		// before any user lookup), so it never enumerates accounts.
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
	}
}

// ---------- Session refresh ----------

type sessionRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type sessionRefreshResponse struct {
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

// HandleSessionRefresh rotates the supplied refresh token via
// UserSessionService.RotateRefreshToken. Wire mappings:
//
//   - 200 + sessionRefreshResponse on success (NEW refresh_token
//     shown EXACTLY ONCE; the supplied one is no longer valid).
//   - 401 {"error":"invalid_grant"} for unknown / expired /
//     revoked / malformed tokens.
//   - 401 {"error":"refresh_reuse_detected"} when the supplied
//     token's selector matches a stored row but the validator
//     does NOT — classic reuse-after-rotation evidence. The
//     service has already revoked every session for the
//     affected user; the wire response is intentionally a
//     distinct sentinel so monitoring can alarm.
func HandleSessionRefresh(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req sessionRefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		issued, err := deps.UserSession.RotateRefreshToken(c.Request.Context(), req.RefreshToken)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrUserSessionReuse):
				_ = deps.Audit.Record(c.Request.Context(), audit.Event{
					Action:    "user_session.refresh.reuse_detected",
					Outcome:   "denied",
					IPAddress: c.ClientIP(),
					UserAgent: c.Request.UserAgent(),
				})
				c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh_reuse_detected"})
			case errors.Is(err, service.ErrUserSessionInvalidGrant):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			}
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.refresh.success",
			Outcome:   "success",
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Metadata: map[string]any{
				"session_id": issued.Session.ID.String(),
			},
		})
		resp := sessionRefreshResponse{
			SessionID:    issued.Session.ID.String(),
			RefreshToken: issued.RefreshToken,
			ExpiresAt:    issued.ExpiresAt.Unix(),
		}
		// Mint a fresh access token when both UserTokenService AND
		// UserLookup are wired. The lookup resolves the session's
		// user_id → *domain.User so the token can stamp
		// email/role/org_id without an extra service-layer round
		// trip.
		if deps.UserToken != nil && deps.UserLookup != nil {
			user, lookupErr := deps.UserLookup.GetByID(c.Request.Context(), issued.Session.UserID)
			if lookupErr == nil && user != nil {
				access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), user, issued.Session)
				if accessErr == nil {
					resp.AccessToken = access.AccessToken
					resp.TokenType = access.TokenType
					resp.ExpiresIn = access.ExpiresIn
				}
			}
		}
		c.JSON(http.StatusOK, resp)
	}
}

// ---------- Logout ----------

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// HandleLogout revokes the session bound to the supplied refresh
// token. Wire mappings:
//
//   - 204 No Content on success.
//   - 204 No Content for unknown / malformed tokens (RFC 7009
//     §2.2 always-200 spirit — logout MUST NOT leak whether a
//     session existed).
//   - 500 only on persistence errors that bypass the sentinel
//     set.
//
// Logout ALWAYS revokes the current server-side session, identified from the
// session the server already resolves from the request — the access_token
// cookie (or Authorization: Bearer), the same source HandleValidateSession
// uses — independent of whether a refresh_token is supplied in the body. A
// subsequent GET /api/v1/validate therefore fails its SessionLookup.GetByID +
// CanBeUsed check (401). Revocation reuses the existing UserSessionService.
// RevokeSession primitive. Best-effort + idempotent: an absent / invalid /
// already-revoked session is a safe no-op (no error leak, no panic), the
// cookies are always cleared, and the response is always 204.
func HandleLogout(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 1. Unconditionally revoke the cookie/bearer-derived current session.
		//    This is the load-bearing change: server-side invalidation no
		//    longer depends on a refresh_token being present in the body.
		if deps.TokenVerifier != nil && deps.UserSession != nil {
			if tok := extractValidateToken(c); tok != "" {
				if principal, err := deps.TokenVerifier.VerifyBearerToken(ctx, tok); err == nil &&
					principal != nil && principal.SessionID != (uuid.UUID{}) {
					_ = deps.UserSession.RevokeSession(ctx, principal.SessionID, "logout")
					_ = deps.Audit.Record(ctx, audit.Event{
						Action:    "user_session.logout",
						Outcome:   "success",
						IPAddress: c.ClientIP(),
						UserAgent: c.Request.UserAgent(),
						Metadata: map[string]any{
							"session_id": principal.SessionID.String(),
						},
					})
				}
			}
		}

		// 2. Optional refresh-token teardown: when the caller still supplies a
		//    refresh_token in the body, rotate-then-revoke its session too so
		//    the refresh-token family is also torn down. NON-GATING — a missing
		//    or invalid body never blocks the cookie-derived revocation above.
		if deps.UserSession != nil {
			var req logoutRequest
			if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
				if issued, rerr := deps.UserSession.RotateRefreshToken(ctx, req.RefreshToken); rerr == nil {
					_ = deps.UserSession.RevokeSession(ctx, issued.Session.ID, "logout")
				}
			}
		}

		clearAuthCookies(c)
		c.Status(http.StatusNoContent)
	}
}

// ---------- Validate session ----------

// validateSessionUserInfo mirrors the monolith's types.UserInfo subset
// the identuum-ui server-session helper reads. We keep the JSON tag
// names byte-compatible with the UI's CurrentUser type so the existing
// `getServerSession()` consumer can continue using its current type.
type validateSessionUserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name,omitempty"`
	Role           string `json:"role"`
	OrganizationID string `json:"organization_id,omitempty"`
	Domain         string `json:"domain,omitempty"`
	Active         bool   `json:"active"`
	Deleted        bool   `json:"deleted"`
	MfaEnabled     bool   `json:"mfa_enabled"`
	EmailVerified  bool   `json:"email_verified"`
}

// validateSessionResponse mirrors the monolith's
// types.ValidateSessionResponse subset the UI reads. `success` + `role`
// at the top level match the wire shape produced by
// HandleValidateSession in identuum-idp/internal/handlers/handler_auth_session.go.
// `user.role` duplicates the field at the top level so callers can use
// either path — identuum-ui's ValidateResponse type currently reads both.
type validateSessionResponse struct {
	Success bool                    `json:"success"`
	Role    string                  `json:"role"`
	User    validateSessionUserInfo `json:"user"`
}

// HandleValidateSession is the OSS implementation of GET /api/v1/validate.
// It returns the authenticated user + role to the UI's server-session
// helper, or 401 on any failure (with NO information about which check
// failed — banned vs deleted vs expired vs malformed all collapse to
// `{"error":"unauthorized"}` to avoid enumeration).
//
// Token resolution order:
//
//  1. `access_token` cookie value, when present.
//  2. `Authorization: Bearer <jwt>` header value, when present.
//
// Validation chain:
//
//  1. TokenVerifier.VerifyBearerToken — JWT signature + claim shape +
//     alg-allowlist (EdDSA / ES256; RS256 and "none" rejected).
//  2. Principal must carry a non-Nil SessionID and UserID.
//  3. SessionLookup.GetByID + session.CanBeUsed(now) — valid +
//     non-revoked + non-expired.
//  4. UserLookup.GetByID — user must exist and not be banned and not
//     soft-deleted.
//
// On success: 200 + the validateSessionResponse JSON above. The token
// itself is NEVER echoed in the response body.
func HandleValidateSession(deps AuthSessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractValidateToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		ctx := c.Request.Context()
		principal, err := deps.TokenVerifier.VerifyBearerToken(ctx, token)
		if err != nil || principal == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if principal.SessionID == (uuid.UUID{}) || principal.UserID == (uuid.UUID{}) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		session, err := deps.SessionLookup.GetByID(ctx, principal.SessionID)
		if err != nil || session == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if ok, _ := session.CanBeUsed(time.Now()); !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		user, err := deps.UserLookup.GetByID(ctx, principal.UserID)
		if err != nil || user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if user.Banned || user.DeletedAt != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		body := validateSessionResponse{
			Success: true,
			Role:    string(user.Role),
			User: validateSessionUserInfo{
				ID:            user.ID.String(),
				Email:         user.Email,
				Role:          string(user.Role),
				Active:        !user.Banned,
				Deleted:       user.DeletedAt != nil,
				MfaEnabled:    user.MFAEnabled,
				EmailVerified: user.EmailVerified,
			},
		}
		if user.OrganizationID != (uuid.UUID{}) {
			body.User.OrganizationID = user.OrganizationID.String()
		}
		if user.Name != nil {
			body.User.Name = *user.Name
		}
		if user.Domain != nil {
			body.User.Domain = *user.Domain
		}
		c.JSON(http.StatusOK, body)
	}
}

// extractValidateToken returns the bearer token to verify: the
// access_token cookie value if present, otherwise the Authorization:
// Bearer header value (case-insensitive `Bearer ` prefix). Returns the
// empty string when neither source is present.
func extractValidateToken(c *gin.Context) string {
	if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
		return cookie
	}
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):]
	}
	return ""
}
