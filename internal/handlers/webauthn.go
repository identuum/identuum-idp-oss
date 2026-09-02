package handlers

// webauthn.go — OSS WebAuthn/passkeys HTTP surface.
//
// Six routes wired here, mirroring the monolith allocation
// (identuum-idp/docs/open-core/IDP_MONOLITH_HANDLER_ALLOCATION_DECISION.md):
//
//   - POST   /api/v1/webauthn/register/begin       (authenticated)
//   - POST   /api/v1/webauthn/register/finish      (authenticated)
//   - GET    /api/v1/webauthn/credentials          (authenticated)
//   - DELETE /api/v1/webauthn/credentials/:id      (authenticated)
//   - POST   /api/v1/auth/login/webauthn/begin     (public)
//   - POST   /api/v1/auth/login/webauthn/finish    (public — issues session+cookies on success)
//
// Source-of-truth for the wire shape is the monolith handler at
// identuum-idp/internal/handlers/handler_webauthn.go. We do NOT
// import monolith code — only the observable contract is preserved.
//
// Cookie + session safety invariants:
//
//   - Registration routes NEVER set Set-Cookie. They only persist
//     a credential row for the already-authenticated principal.
//   - Login-finish ONLY sets cookies AFTER the assertion verifies
//     AND the credential survives every guard (clone-warning,
//     tenant match, sign-count update). The cookie path uses the
//     same setAuthCookies helper as the password and MFA flows so
//     the UI sees a uniform contract.
//   - Registration begin/finish + login begin/finish persist the
//     session_id via the short-lived ceremony store (5 minutes);
//     every session is consumed (single-use) on finish via Delete.
//
// Secrets safety:
//
//   - Raw challenges, attestation objects, assertion responses,
//     credential bytes, and the upstream session token are NEVER
//     logged in this file. Audit metadata carries only the
//     credential's database id (UUIDv7) and the user id — both
//     non-sensitive correlation handles.
//   - The credential list response NEVER includes the credential's
//     raw public key, credential_id, or attestation object. It
//     exposes only safe display fields (db id, created_at,
//     last_used_at, aaguid, clone_warning).
//
// Anti-enumeration:
//
//   The public login-begin path returns a structurally
//   indistinguishable dummy assertion when the supplied email
//   matches zero OR more than one user. The wire response cannot
//   be used as an account-existence oracle.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// WebAuthnLoginFinisher is the narrow seam HandleWebAuthnLoginFinish
// consumes. *service.WebAuthnService satisfies it; using an interface (not
// the concrete service) keeps the seal + MFA policy gate testable. The
// third return is the assertion's user-verification (UV) flag.
type WebAuthnLoginFinisher interface {
	FinishLogin(ctx context.Context, sessionID string, request *http.Request) (*domain.WebAuthnCredential, *domain.User, bool, error)
}

// WebAuthnUserOrgLookup resolves a user WITH its organization policy
// fields (auth_policy, mfa_policy) projected — the WebAuthn user-resolution
// uses the org-less GetByID, so the login-finish handler reloads the
// org-bearing projection to evaluate the idp_only seal + MFA policy.
// *repository.UserRepository satisfies it via GetByIDWithOrg.
type WebAuthnUserOrgLookup interface {
	GetByIDWithOrg(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// WebAuthnHandlerDeps wires the WebAuthn route family. All routes
// require WebAuthnService non-nil. The login-finish route also
// requires UserSession (for session/refresh-token minting) and
// UserToken (for access-token minting); when either is nil the
// public login routes do NOT register. UserLookup is required by
// the login-finish flow to resolve the credential's user. Audit
// defaults to NoopService when nil.
type WebAuthnHandlerDeps struct {
	WebAuthn    *service.WebAuthnService
	UserSession *service.UserSessionService
	UserToken   *service.UserTokenService
	UserLookup  UserByIDLookup
	Audit       audit.Service

	// LoginFinisher is the testable seam for the login-finish assertion.
	// nil falls back to WebAuthn (production wires it to the same service).
	LoginFinisher WebAuthnLoginFinisher
	// UserOrgLookup reloads the org-bearing user projection so the
	// login-finish path can enforce the idp_only AuthPolicy seal + the
	// org MFA policy. nil ⇒ the seal/MFA gate treats policy as the
	// permissive default (no org policy available — scaffold deployments).
	UserOrgLookup WebAuthnUserOrgLookup

	// R7: per-IP rate limiters on ceremony routes. When nil, no rate
	// limiting is applied (safe for test environments where
	// OSSRouterDeps.RateLimitConfig is zero-value).
	// Production wiring: ancestor thresholds — LoginLimiter 5/1m,
	// RegisterLimiter 10/1h (keyed on c.ClientIP() — proxy-aware).
	LoginLimiter    gin.HandlerFunc
	RegisterLimiter gin.HandlerFunc
}

// RegisterWebAuthnRoutes mounts the WebAuthn route family.
//
// Registration + credential management routes register unconditionally
// when WebAuthn is wired — the authentication gate is enforced inside
// the handler (we cannot mount RequireAuthenticated as a middleware
// without also wiring BearerPrincipal, which is the router's job).
//
// Login routes register only when the full chain
// (UserSession + UserToken + UserLookup) is available — otherwise the
// success path could not issue cookies and the route would be
// effectively dead.
//
// R7: per-IP rate limiters are applied via Gin sub-groups so the route
// registration lines remain in the form handler(deps) — docgen can
// extract the correct handler symbol from the call site.
func RegisterWebAuthnRoutes(router gin.IRouter, deps WebAuthnHandlerDeps) {
	if deps.WebAuthn == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	// R7: sub-groups carry the per-IP rate limiter as group middleware.
	// When the limiter is nil (zero-value RateLimitConfig / test env),
	// Use is not called and the group behaves identically to router.
	regGroup := router.Group("")
	if deps.RegisterLimiter != nil {
		regGroup.Use(deps.RegisterLimiter)
	}

	// docgen:endpoint
	// docgen:surface=webauthn
	// docgen:method=POST
	// docgen:path=/api/v1/webauthn/register/begin
	// docgen:summary=Start a WebAuthn passkey registration ceremony for the authenticated user. Returns the browser's PublicKeyCredentialCreationOptions plus an opaque session_id for the matching /register/finish call. Challenge is short-lived (5 minutes) and single-use.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=No Set-Cookie is written. Challenge bytes never appear in logs or audit metadata.
	regGroup.POST("/api/v1/webauthn/register/begin", HandleWebAuthnRegisterBegin(deps))
	// docgen:endpoint
	// docgen:surface=webauthn
	// docgen:method=POST
	// docgen:path=/api/v1/webauthn/register/finish
	// docgen:summary=Complete a WebAuthn passkey registration ceremony. Consumes the session_id query parameter (single-use); the request body is the browser's attestation response. On success persists a credential row bound to the authenticated user and emits a webauthn_credential_registered audit event.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Session id is consumed on every exit path (single-use). Attestation object and raw credential material are never logged. NO login session is created here — registration only persists the credential.
	regGroup.POST("/api/v1/webauthn/register/finish", HandleWebAuthnRegisterFinish(deps))
	// docgen:endpoint
	// docgen:surface=webauthn
	// docgen:method=GET
	// docgen:path=/api/v1/webauthn/credentials
	// docgen:summary=List the authenticated user's WebAuthn credentials. Safe projection — never exposes the raw credential id, public key, or attestation object.
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:notes=Response carries only id (db UUIDv7), created_at, last_used_at, aaguid, clone_warning.
	router.GET("/api/v1/webauthn/credentials", HandleListWebAuthnCredentials(deps))
	// docgen:endpoint
	// docgen:surface=webauthn
	// docgen:method=DELETE
	// docgen:path=/api/v1/webauthn/credentials/:id
	// docgen:summary=Delete one of the authenticated user's WebAuthn credentials by its database id. Ownership-enforced — a credential the caller does not own returns 404 (no enumeration).
	// docgen:tier=oss
	// docgen:auth=session
	// docgen:status=204
	router.DELETE("/api/v1/webauthn/credentials/:id", HandleDeleteWebAuthnCredential(deps))

	if deps.UserSession != nil && deps.UserToken != nil && deps.UserLookup != nil {
		loginGroup := router.Group("")
		if deps.LoginLimiter != nil {
			loginGroup.Use(deps.LoginLimiter)
		}
		// docgen:endpoint
		// docgen:surface=webauthn
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login/webauthn/begin
		// docgen:summary=Begin a WebAuthn login ceremony for an email. Returns a CredentialAssertion + opaque session_id. Anti-enumeration — zero or multiple matches both return a structurally indistinguishable dummy assertion.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=No Set-Cookie. Challenge bytes never logged. Dummy path is invisible to the caller.
		loginGroup.POST("/api/v1/auth/login/webauthn/begin", HandleWebAuthnLoginBegin(deps))
		// docgen:endpoint
		// docgen:surface=webauthn
		// docgen:method=POST
		// docgen:path=/api/v1/auth/login/webauthn/finish
		// docgen:summary=Finish a WebAuthn login ceremony. Consumes the session_id query parameter (single-use); the request body is the browser's assertion response. On success issues a user session + Set-Cookie access_token (and refresh_token when remember_me=true on the query). All failure modes collapse to 401 invalid_credentials.
		// docgen:tier=oss
		// docgen:auth=public
		// docgen:notes=Cookies are written ONLY after the assertion verifies AND every guard (clone-warning, tenant match) passes. Raw assertion + session id are never logged.
		loginGroup.POST("/api/v1/auth/login/webauthn/finish", HandleWebAuthnLoginFinish(deps))
	}
}

// ---------- Helpers ----------

// authenticatedUserID extracts the principal's user id from the
// gin context. Returns uuid.Nil + false when no principal is
// attached or when the principal carries no user id. The handlers
// here always respond 401 in that case.
func authenticatedUserID(c *gin.Context) (uuid.UUID, bool) {
	p, ok := mw.PrincipalFromContext(c)
	if !ok || p == nil {
		return uuid.Nil, false
	}
	if p.UserID == uuid.Nil {
		return uuid.Nil, false
	}
	return p.UserID, true
}

// rejectUnauthenticated writes the same 401 body used elsewhere in
// the OSS auth surface so error shapes are consistent.
func rejectUnauthenticated(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

// ---------- POST /api/v1/webauthn/register/begin ----------

type webAuthnRegisterBeginResponse struct {
	Success   bool        `json:"success"`
	PublicKey interface{} `json:"publicKey"`
	SessionID string      `json:"session_id"`
}

// HandleWebAuthnRegisterBegin starts a registration ceremony for
// the authenticated principal. Returns 401 when unauthenticated,
// 500 on unexpected service errors. The credential creation
// options are echoed back to the browser; the session_id is opaque
// and must be sent back to /register/finish.
func HandleWebAuthnRegisterBegin(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	lookup := deps.UserLookup
	return func(c *gin.Context) {
		userID, ok := authenticatedUserID(c)
		if !ok {
			rejectUnauthenticated(c)
			return
		}
		user, err := loadUserForWebAuthn(c, lookup, userID)
		if err != nil || user == nil {
			rejectUnauthenticated(c)
			return
		}
		creation, sessionID, err := deps.WebAuthn.BeginRegistration(c.Request.Context(), user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.JSON(http.StatusOK, webAuthnRegisterBeginResponse{
			Success:   true,
			PublicKey: creation.Response,
			SessionID: sessionID,
		})
	}
}

// loadUserForWebAuthn resolves the principal back to a *domain.User
// via the existing UserByIDLookup seam. The seam is OPTIONAL in
// the OSS dep bundle for registration begin/finish (a deployment
// that wires WebAuthn without UserLookup will simply reject the
// request — we never want to mutate credentials without a fresh
// authoritative user row), so the helper returns nil for that
// case. The login-finish path uses the same seam.
func loadUserForWebAuthn(c *gin.Context, lookup UserByIDLookup, userID uuid.UUID) (*domain.User, error) {
	if lookup == nil {
		return nil, errors.New("webauthn: user lookup not wired")
	}
	return lookup.GetByID(c.Request.Context(), userID)
}

// ---------- POST /api/v1/webauthn/register/finish ----------

type webAuthnRegisterFinishResponse struct {
	Success      bool   `json:"success"`
	Status       string `json:"status"`
	CredentialID string `json:"credential_id"`
}

// HandleWebAuthnRegisterFinish completes a registration ceremony.
//
// session_id is read from the query string (matching the monolith
// contract). The request body is the upstream library's attestation
// response; gin's http.Request is forwarded directly so the library
// can read clientDataJSON / attestationObject without re-parsing.
func HandleWebAuthnRegisterFinish(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	lookup := deps.UserLookup
	return func(c *gin.Context) {
		userID, ok := authenticatedUserID(c)
		if !ok {
			rejectUnauthenticated(c)
			return
		}
		user, err := loadUserForWebAuthn(c, lookup, userID)
		if err != nil || user == nil {
			rejectUnauthenticated(c)
			return
		}
		sessionID := c.Query("session_id")
		if sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		nickname := strings.TrimSpace(c.Query("nickname"))
		if len(nickname) > 80 {
			nickname = nickname[:80] // match the schema VARCHAR(80) cap
		}
		cred, err := deps.WebAuthn.FinishRegistrationWithNickname(c.Request.Context(), user, sessionID, c.Request, nickname)
		if err != nil {
			if errors.Is(err, service.ErrWebAuthnSessionInvalid) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
				return
			}
			// Library-side verification failures + unexpected
			// repo errors both collapse to 400 invalid_request —
			// we MUST NOT distinguish "your attestation is bad"
			// from "the server hiccuped" on the wire.
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		c.JSON(http.StatusOK, webAuthnRegisterFinishResponse{
			Success:      true,
			Status:       "created",
			CredentialID: cred.ID.String(),
		})
	}
}

// ---------- GET /api/v1/webauthn/credentials ----------

type webAuthnCredentialView struct {
	ID           uuid.UUID  `json:"id"`
	Nickname     string     `json:"nickname"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	AAGUID       string     `json:"aaguid"`
	CloneWarning bool       `json:"clone_warning"`
}

// HandleListWebAuthnCredentials returns the safe-projection list of
// credentials owned by the authenticated user. Never exposes the
// raw credential id or the public key.
func HandleListWebAuthnCredentials(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := authenticatedUserID(c)
		if !ok {
			rejectUnauthenticated(c)
			return
		}
		creds, err := deps.WebAuthn.ListCredentials(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		out := make([]webAuthnCredentialView, 0, len(creds))
		for _, cred := range creds {
			aaguid := ""
			if cred.AAGUID != nil {
				aaguid = cred.AAGUID.String()
			}
			out = append(out, webAuthnCredentialView{
				ID:           cred.ID,
				Nickname:     cred.Nickname,
				CreatedAt:    cred.CreatedAt,
				LastUsedAt:   cred.LastUsedAt,
				AAGUID:       aaguid,
				CloneWarning: cred.CloneWarning,
			})
		}
		c.JSON(http.StatusOK, out)
	}
}

// ---------- DELETE /api/v1/webauthn/credentials/:id ----------

// HandleDeleteWebAuthnCredential deletes a credential. The handler
// returns 404 on ownership failures (matching the service's
// ErrResourceNotFound semantics) — the wire response cannot
// distinguish "credential is yours but missing" from "credential
// exists but belongs to someone else".
func HandleDeleteWebAuthnCredential(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := authenticatedUserID(c)
		if !ok {
			rejectUnauthenticated(c)
			return
		}
		credID, err := uuid.Parse(c.Param("id"))
		if err != nil || credID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if err := deps.WebAuthn.DeleteCredential(c.Request.Context(), userID, credID); err != nil {
			if errors.Is(err, domain.ErrResourceNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// ---------- POST /api/v1/auth/login/webauthn/begin ----------

type webAuthnLoginBeginRequest struct {
	Email string `json:"email"`
}

type webAuthnLoginBeginResponse struct {
	Success   bool        `json:"success"`
	PublicKey interface{} `json:"publicKey"`
	SessionID string      `json:"session_id"`
}

// HandleWebAuthnLoginBegin starts a login ceremony for an email.
// Anti-enumeration: zero or multiple matches fall through to the
// dummy assertion path so the response is structurally identical
// whether the email exists, is shared across orgs, or does not
// exist at all.
func HandleWebAuthnLoginBegin(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req webAuthnLoginBeginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		if req.Email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		user, err := deps.WebAuthn.FindUserByEmail(c.Request.Context(), req.Email)
		if err != nil {
			// Hard repo error — still fall through to dummy to
			// avoid an oracle. The dummy response is harmless.
			user = nil
		}
		if user == nil {
			assertion, sessionID := deps.WebAuthn.BeginDummyLogin(c.Request.Context())
			c.JSON(http.StatusOK, webAuthnLoginBeginResponse{
				Success:   true,
				PublicKey: assertion.Response,
				SessionID: sessionID,
			})
			return
		}
		assertion, sessionID, err := deps.WebAuthn.BeginLogin(c.Request.Context(), user)
		if err != nil {
			// ErrWebAuthnNoCredentials and any other failure
			// mode also fall through to the dummy path —
			// distinguishing them would create an oracle on
			// "user exists but has no passkey".
			assertion, sessionID := deps.WebAuthn.BeginDummyLogin(c.Request.Context())
			c.JSON(http.StatusOK, webAuthnLoginBeginResponse{
				Success:   true,
				PublicKey: assertion.Response,
				SessionID: sessionID,
			})
			return
		}
		c.JSON(http.StatusOK, webAuthnLoginBeginResponse{
			Success:   true,
			PublicKey: assertion.Response,
			SessionID: sessionID,
		})
	}
}

// ---------- POST /api/v1/auth/login/webauthn/finish ----------

type webAuthnLoginFinishResponse struct {
	UserID       string `json:"user_id"`
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Role         string `json:"role,omitempty"`
	Email        string `json:"email,omitempty"`
}

// HandleWebAuthnLoginFinish verifies the assertion, mints a session
// + access token, and writes Set-Cookie. All failure modes collapse
// onto 401 invalid_credentials — the wire response NEVER tells the
// caller which guard tripped.
//
// remember_me is read from the query string (?remember_me=true) so
// the contract matches the monolith. When absent the refresh
// cookie is a session cookie (MaxAge=0).
func HandleWebAuthnLoginFinish(deps WebAuthnHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Query("session_id")
		if sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		finisher := WebAuthnLoginFinisher(deps.WebAuthn)
		if deps.LoginFinisher != nil {
			finisher = deps.LoginFinisher
		}
		_, user, userVerified, err := finisher.FinishLogin(c.Request.Context(), sessionID, c.Request)
		if err != nil || user == nil {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user_session.login.webauthn_failure",
				Outcome:   "denied",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
		// Reload the org-bearing user projection (auth_policy + mfa_policy)
		// for the policy gates below. FinishLogin already verified the
		// assertion AND that the user is active/non-banned; this reload
		// only adds org-policy fields (the WebAuthn user-resolution uses
		// the org-less GetByID). Best-effort: nil seam or error leaves
		// the org policy at its permissive default.
		if deps.UserOrgLookup != nil {
			if orgUser, lookupErr := deps.UserOrgLookup.GetByIDWithOrg(c.Request.Context(), user.ID); lookupErr == nil && orgUser != nil {
				user = orgUser
			}
		}
		// (1) idp_only AuthPolicy SEAL — a WebAuthn passkey IS a local
		// credential, so the exact seal OSS password login enforces
		// (service.IsLocalCredentialFlowAllowed) applies here. An idp_only
		// org blocks org_user WebAuthn login just as it blocks password
		// login; site_admin / org_admin retain local credential access.
		// Denial collapses to the same generic invalid_credentials the
		// password path returns — no session is created.
		orgAuthPolicy := ""
		if user.OrgAuthPolicy != nil {
			orgAuthPolicy = *user.OrgAuthPolicy
		}
		if decision := service.IsLocalCredentialFlowAllowed(user, orgAuthPolicy); !decision.Allowed {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user_session.login.webauthn_policy_denied",
				Outcome:   "denied",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				ActorID:   user.ID,
				SubjectID: user.ID,
				Metadata:  map[string]any{"reason": "idp_only_auth_policy"},
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
		// (2) MFA POLICY (UV-conditional) — when the org policy requires
		// MFA, a WebAuthn assertion satisfies that requirement IF AND ONLY
		// IF it included user verification (UV). A UV-verified assertion is
		// a strong, phishing-resistant factor → MFA satisfied, no second
		// factor. A presence-only assertion (no UV) does NOT satisfy MFA →
		// the login does NOT complete as fully authenticated; no session is
		// created and a second factor is required.
		if service.IsMFARequiredForUser(user) && !userVerified {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:    "user_session.login.webauthn_mfa_required",
				Outcome:   "denied",
				IPAddress: c.ClientIP(),
				UserAgent: c.Request.UserAgent(),
				ActorID:   user.ID,
				SubjectID: user.ID,
				Metadata:  map[string]any{"reason": "mfa_required_uv_absent"},
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "mfa_required"})
			return
		}
		rememberMe := c.Query("remember_me") == "true"
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
		if user.OrgMaxSessionsPerUser != nil {
			maxSessions = *user.OrgMaxSessionsPerUser
		}
		// THE-HONEST-ACR: a verified WebAuthn assertion is the
		// phishing-resistant rung (the ladder's top; it satisfies any
		// requested rung). Not advertised in acr_values_supported — only
		// the password and password+TOTP contexts are.
		issued, err := deps.UserSession.CreateUserSession(c.Request.Context(), service.CreateUserSessionInput{
			UserID:             user.ID,
			IPAddress:          ipPtr,
			UserAgent:          uaPtr,
			RememberMe:         rememberMe,
			Acr:                auth.ACRPhishingResistant,
			MaxSessionsPerUser: maxSessions,
			OrganizationID:     user.OrganizationID,
			Role:               string(user.Role),
		})
		if err != nil || issued == nil || issued.Session == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:    "user_session.login.webauthn_success",
			Outcome:   "success",
			IPAddress: ip,
			UserAgent: ua,
			ActorID:   user.ID,
			SubjectID: user.ID,
			Metadata: map[string]any{
				"user_id":    user.ID.String(),
				"session_id": issued.Session.ID.String(),
			},
		})
		resp := webAuthnLoginFinishResponse{
			UserID:       user.ID.String(),
			SessionID:    issued.Session.ID.String(),
			RefreshToken: issued.RefreshToken,
			ExpiresAt:    issued.Session.ExpiresAt.Unix(),
			Role:         string(user.Role),
			Email:        user.Email,
		}
		if deps.UserToken != nil {
			access, accessErr := deps.UserToken.IssueForSession(c.Request.Context(), user, issued.Session)
			if accessErr == nil && access != nil {
				resp.AccessToken = access.AccessToken
				resp.TokenType = access.TokenType
				resp.ExpiresIn = access.ExpiresIn
			}
		}
		setAuthCookies(c, resp.AccessToken, resp.RefreshToken, rememberMe)
		c.JSON(http.StatusOK, resp)
	}
}
