package handlers

// sessions.go — OSS session list / revoke surface ported from the
// monolith.
//
// Source-of-truth references for wire shape:
//   identuum-idp/internal/handlers/handler_sessions.go      (GET /api/v1/sessions)
//   identuum-idp/internal/handlers/handler_auth_session.go  (POST /api/v1/revoke {session_id} branch)
//   identuum-ui/src/lib/idp-admin-client.ts                 (SessionItem typescript shape)
//
// Routes mounted:
//
//   GET  /api/v1/sessions
//       response: 200 {"success":true,"sessions":[SessionItem,...]}
//       Lists ACTIVE sessions belonging to the authenticated user.
//       Banned / deleted users are rejected at the principal-load
//       stage by the bearer middleware that runs before this
//       handler. site_admin role returns 403 by design (cross-
//       tenant isolation — site_admin sessions appear via the
//       commercial /api/v1/system/sessions route, not this one).
//
//   POST /api/v1/revoke
//       request:  { "session_id": "<uuid>" }
//       response: 200 {"success":true,"message":"Session revoked"}
//       Revokes one session owned by the authenticated user. Wire
//       contract intentionally returns 200 for unknown / already-
//       revoked / cross-user session ids (idempotent, anti-
//       enumeration). Internal repo errors return 500.
//
// Auth + safety invariants (load-bearing — do not relax):
//
//   - The authenticated principal MUST own the session being
//     revoked. Cross-user revocation is silently rejected — the
//     wire response is the same {success:true,"message":"Session
//     revoked"} so a hostile caller cannot probe whether a given
//     UUID is a real session belonging to another user.
//   - Current-session revocation is allowed (the operator may
//     forcibly log themselves out of THIS browser tab). The
//     response carries `current_revoked: true` so the UI can
//     decide whether to redirect the operator to /login.
//   - No session token / cookie / selector / validator hash /
//     refresh-token-rotation material is ever returned in the
//     list or revoke response. The list projection is verified by
//     a defensive test (TestSessions_NoCredentialMaterial).
//   - site_admin returns 403 on both routes by design — the
//     account-settings sessions list is for tenant operators
//     only. This matches the monolith RequireScopesAny posture.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// SessionsHandlerDeps wires the session list/revoke routes.
//
// SessionLookup + SessionList are REQUIRED — the routes do not
// register when either is nil. Revoker is REQUIRED on the
// POST /revoke route only; when nil, the list route still works
// but the revoke route returns 404.
//
// Audit defaults to NoopService inside Register.
type SessionsHandlerDeps struct {
	SessionList SessionListLookup
	SessionRepo SessionByIDLookup // re-uses the existing SessionByIDLookup seam from token.go
	UserSession SessionRevoker
	Audit       audit.Service
}

// SessionListLookup is the narrow seam the list handler consumes.
// repository.SessionRepository satisfies it via ListByUserID.
type SessionListLookup interface {
	ListByUserID(ctx context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error)
}

// SessionRevoker is the narrow seam the revoke handler consumes.
// *service.UserSessionService satisfies it via RevokeSession.
type SessionRevoker interface {
	RevokeSession(ctx context.Context, sessionID uuid.UUID, reason string) error
}

// Compile-time assertions: the production seams remain satisfied
// even when these interface declarations evolve.
var _ SessionListLookup = repository.SessionRepository(nil)
var _ SessionRevoker = (*service.UserSessionService)(nil)

// RegisterSessionsRoutes mounts:
//
//	GET  /api/v1/sessions
//	POST /api/v1/revoke
//
// onto router. Both routes ONLY register when their required deps
// are wired — partial deployments degrade gracefully.
func RegisterSessionsRoutes(router gin.IRouter, deps SessionsHandlerDeps) {
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.SessionList != nil && deps.SessionRepo != nil {
		// docgen:endpoint
		// docgen:surface=sessions
		// docgen:method=GET
		// docgen:path=/api/v1/sessions
		// docgen:summary=List the authenticated user's own sessions. Safe projection — never returns session tokens, selectors, validator hashes, or refresh-token material. Cross-tenant isolation — site_admin role returns 403 by design.
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Body shape is {success, sessions:[]} where each SessionItem carries id / created_at / expires_at / last_used_at / ip_address / user_agent / is_active / is_current. UI uses `id` as a revoke handle only; it must not be rendered as visible text.
		router.GET("/api/v1/sessions", HandleListOwnSessions(deps))
	}
	if deps.UserSession != nil && deps.SessionRepo != nil {
		// docgen:endpoint
		// docgen:surface=sessions
		// docgen:method=POST
		// docgen:path=/api/v1/revoke
		// docgen:summary=Revoke a session owned by the authenticated user. Idempotent — unknown / already-revoked / cross-user session ids all return 200 success without disclosure (anti-enumeration). Current session revocation is allowed and signalled via current_revoked:true.
		// docgen:tier=oss
		// docgen:auth=session
		// docgen:notes=Request body {session_id:"<uuid>"}. Cross-user revocation is silently rejected (wire-indistinguishable from a successful revoke). site_admin returns 403 by design. No Set-Cookie is written. Audit metadata carries only the session id and reason — never the session token or selector.
		router.POST("/api/v1/revoke", HandleRevokeOwnSession(deps))
	}
}

// ---------- GET /api/v1/sessions ----------

// sessionItemView mirrors the identuum-ui SessionItem TypeScript
// shape (idp-admin-client.ts). Field names + casing are stable
// wire contract — do not rename.
type sessionItemView struct {
	ID         string  `json:"id"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  string  `json:"expires_at"`
	LastUsedAt *string `json:"last_used_at"`
	IPAddress  *string `json:"ip_address"`
	UserAgent  *string `json:"user_agent"`
	IsActive   bool    `json:"is_active"`
	IsCurrent  bool    `json:"is_current"`
}

type listSessionsResponse struct {
	Success  bool              `json:"success"`
	Sessions []sessionItemView `json:"sessions"`
}

// HandleListOwnSessions returns the authenticated user's own
// sessions. Wire mappings:
//
//   - 200 listSessionsResponse on success.
//   - 401 unauthorized when no principal is attached / the
//     principal carries no UserID.
//   - 403 forbidden when the principal carries the site_admin
//     role (cross-tenant isolation — site_admin sessions are
//     listed via the commercial /system/sessions route).
//   - 500 internal_error on unexpected repo failure.
func HandleListOwnSessions(deps SessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if principal.IsSiteAdmin() {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		// includeInvalid=false → ListByUserID returns only
		// currently-active sessions (the row is dropped by the repo
		// when revoked_at != nil OR expires_at < now). The wire
		// contract documents this — the UI does not render expired
		// rows.
		sessions, err := deps.SessionList.ListByUserID(c.Request.Context(), principal.UserID, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		now := time.Now()
		out := make([]sessionItemView, 0, len(sessions))
		for _, sess := range sessions {
			if sess == nil {
				continue
			}
			view := sessionItemView{
				ID:        sess.ID.String(),
				CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
				ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
				IPAddress: sess.IPAddress,
				UserAgent: sess.UserAgent,
				IsCurrent: sess.ID == principal.SessionID,
			}
			if sess.LastUsedAt != nil {
				t := sess.LastUsedAt.UTC().Format(time.RFC3339)
				view.LastUsedAt = &t
			}
			// CanBeUsed mirrors the production validity gate the
			// auth-validate route uses. A row whose ExpiresAt is
			// past — but which the repo still returned because it
			// has not yet been swept — is reported is_active=false.
			active, _ := sess.CanBeUsed(now)
			view.IsActive = active
			out = append(out, view)
		}
		c.JSON(http.StatusOK, listSessionsResponse{Success: true, Sessions: out})
	}
}

// ---------- POST /api/v1/revoke ----------

type revokeSessionRequest struct {
	SessionID string `json:"session_id"`
}

type revokeSessionResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	CurrentRevoked bool   `json:"current_revoked,omitempty"`
}

// HandleRevokeOwnSession revokes a session owned by the
// authenticated principal. Wire mappings:
//
//   - 200 revokeSessionResponse on success AND on every
//     anti-enumeration failure (unknown / cross-user / already-
//     revoked / malformed-uuid). Current-session revocation
//     additionally carries current_revoked:true so the UI knows
//     to redirect to /login.
//   - 400 invalid_request on malformed JSON.
//   - 401 unauthorized when no principal is attached.
//   - 403 forbidden when site_admin (cross-tenant isolation).
//   - 500 internal_error on unexpected repo failure during
//     ownership lookup or revoke.
//
// Anti-enumeration: a cross-user session id returns the same body
// as a successful revoke. A hostile caller cannot probe which
// UUIDs map to real foreign sessions.
func HandleRevokeOwnSession(deps SessionsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, ok := mw.PrincipalFromContext(c)
		if !ok || principal == nil || principal.UserID == uuid.Nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if principal.IsSiteAdmin() {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		var req revokeSessionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
		sessionID, err := uuid.Parse(req.SessionID)
		if err != nil || sessionID == uuid.Nil {
			// Malformed UUID → same opaque success body as the
			// other anti-enumeration paths. The handler MUST
			// NOT signal "this string is not a uuid" — that
			// would be a weak probe oracle.
			c.JSON(http.StatusOK, revokeSessionResponse{Success: true, Message: "Session revoked"})
			return
		}
		sess, err := deps.SessionRepo.GetByID(c.Request.Context(), sessionID)
		if err != nil {
			if errors.Is(err, domain.ErrSessionNotFound) {
				c.JSON(http.StatusOK, revokeSessionResponse{Success: true, Message: "Session revoked"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		// Ownership guard. Cross-user revocation is silently
		// rejected with the same body as a successful revoke.
		if sess == nil || sess.UserID != principal.UserID {
			c.JSON(http.StatusOK, revokeSessionResponse{Success: true, Message: "Session revoked"})
			return
		}
		// Already-revoked → idempotent success.
		if sess.RevokedAt != nil {
			c.JSON(http.StatusOK, revokeSessionResponse{Success: true, Message: "Session revoked"})
			return
		}
		isCurrent := sess.ID == principal.SessionID
		if err := deps.UserSession.RevokeSession(c.Request.Context(), sess.ID, "user_requested"); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		_ = deps.Audit.Record(c.Request.Context(), audit.Event{
			Action:         "user_session.revoke.success",
			Outcome:        "success",
			SubjectID:      sess.ID,
			SubjectType:    "session",
			ActorID:        principal.UserID,
			OrganizationID: principal.OrganizationID,
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"session_id": sess.ID.String(),
				"reason":     "user_requested",
				"current":    isCurrent,
			},
		})
		c.JSON(http.StatusOK, revokeSessionResponse{
			Success:        true,
			Message:        "Session revoked",
			CurrentRevoked: isCurrent,
		})
	}
}
