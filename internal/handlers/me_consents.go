package handlers

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
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// MeConsentService is the consent store the self-service routes read and
// revoke through. *service.ConsentService satisfies it.
type MeConsentService interface {
	ListForUser(ctx context.Context, userID uuid.UUID) ([]service.ClientConsent, error)
	HasActiveForClient(ctx context.Context, userID uuid.UUID, clientID string) (bool, error)
	RevokeClient(ctx context.Context, userID uuid.UUID, clientID string) (int64, error)
}

// MeConsentRefreshRevoker ends a user's refresh tokens for one application
// and denylists the access tokens linked to them. *service.RefreshTokenService
// satisfies it.
type MeConsentRefreshRevoker interface {
	RevokeAllForUserClient(ctx context.Context, userID uuid.UUID, clientID string) (int64, error)
}

// MeConsentClientLookup names a live application. It answers
// domain.ErrClientNotFound for a deleted one.
type MeConsentClientLookup interface {
	GetClientByClientID(ctx context.Context, clientID string) (*domain.Client, error)
}

// MeConsentsHandlerDeps wires the self-service consent routes (D3). All are
// required; the routes are absent when one is nil.
type MeConsentsHandlerDeps struct {
	Consents   MeConsentService
	Refresh    MeConsentRefreshRevoker
	Clients    MeConsentClientLookup
	UserLookup UserByIDLookup
	Audit      audit.Service
	// AccessTokenLifetime is how long an access token already issued to an
	// application stays valid; the list shows it so the person knows what
	// removing access does not end at once.
	AccessTokenLifetime time.Duration
}

// RegisterMeConsentRoutes mounts the caller's own consents under
// /api/v1/me/consents behind mw.RequireAuthenticated (D3, owner answer Q5
// (a)). The user is taken only from the authenticated principal: a user_id in
// the query or a request body is refused, as on POST
// /api/v1/me/sessions/revoke-all (OSS-O18-CSRF-CHECK).
func RegisterMeConsentRoutes(router gin.IRouter, deps MeConsentsHandlerDeps) {
	if deps.Consents == nil || deps.Refresh == nil || deps.Clients == nil || deps.UserLookup == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}
	if deps.AccessTokenLifetime <= 0 {
		deps.AccessTokenLifetime = time.Hour
	}
	g := router.Group("/api/v1/me/consents")
	g.Use(mw.RequireAuthenticated())
	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=GET
	// docgen:path=/api/v1/me/consents
	// docgen:summary=Self-service list of the applications the authenticated user has given access to: one entry per application with its name, the scopes granted across its audiences, and when access was first and last granted.
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=Response {"consents":[{"client_id","name","scopes":[...],"first_granted_at","last_granted_at"}],"access_token_lifetime_seconds":N}; times are RFC 3339. Only the caller's ACTIVE consents on LIVE applications are listed: revoked consents, deleted applications and other users' consents never appear. access_token_lifetime_seconds is how long an access token already issued to an application stays valid. The route accepts no request body and no user_id query parameter; the user is derived only from the authenticated principal. Cache-Control no-store + Pragma no-cache.
	g.GET("", HandleListOwnConsents(deps))
	// docgen:endpoint
	// docgen:surface=auth
	// docgen:method=DELETE
	// docgen:path=/api/v1/me/consents/:client_id
	// docgen:summary=Self-service removal of an application's access: revokes the authenticated user's consent for the application on every audience and ends the user's refresh tokens for it, so the application asks again at its next sign-in.
	// docgen:tier=oss
	// docgen:auth=authenticated
	// docgen:notes=204 No Content on success. The access tokens linked to the ended refresh tokens are denylisted; an access token issued without a refresh token stays valid until it expires (access_token_lifetime_seconds of the list). An application the caller has no active consent for, another user's, an unknown client_id or a deleted application answers 404 {"error":"not_found","message":"You have not given this application access."} and revokes nothing. 503 {"error":"temporarily_unavailable"} when the refresh tokens could not be ended; the consent is then kept, so a retry completes the removal. The route accepts no request body and no user_id query parameter; the user is derived only from the authenticated principal. Audited as self_consent_revoked (actor and subject the caller; metadata client_id and counts, never a token). Cache-Control no-store + Pragma no-cache.
	// docgen:status=204
	g.DELETE("/:client_id", HandleRevokeOwnConsent(deps))
}

// meConsentView is one listed application.
type meConsentView struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	FirstGrantedAt string   `json:"first_granted_at"`
	LastGrantedAt  string   `json:"last_granted_at"`
}

// meConsentCaller answers the authenticated, live caller, or writes the
// refusal and answers nil.
func meConsentCaller(c *gin.Context, deps MeConsentsHandlerDeps) *domain.User {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	principal, ok := mw.PrincipalFromContext(c)
	if !ok || principal == nil || principal.UserID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil
	}
	if _, present := c.Request.URL.Query()["user_id"]; present || requestHasBody(c) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return nil
	}
	user, err := deps.UserLookup.GetByID(c.Request.Context(), principal.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
		return nil
	}
	if user == nil || user.ID != principal.UserID || user.Banned || user.DeletedAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil
	}
	return user
}

// HandleListOwnConsents serves GET /api/v1/me/consents.
func HandleListOwnConsents(deps MeConsentsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := meConsentCaller(c, deps)
		if user == nil {
			return
		}
		consents, err := deps.Consents.ListForUser(c.Request.Context(), user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		out := make([]meConsentView, 0, len(consents))
		for _, cc := range consents {
			client, err := deps.Clients.GetClientByClientID(c.Request.Context(), cc.ClientID)
			if errors.Is(err, domain.ErrClientNotFound) || (err == nil && client == nil) {
				continue // a deleted application is not listed
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
				return
			}
			out = append(out, meConsentView{
				ClientID:       cc.ClientID,
				Name:           client.Name,
				Scopes:         append([]string{}, cc.Scopes...),
				FirstGrantedAt: cc.FirstGrantedAt.UTC().Format(time.RFC3339),
				LastGrantedAt:  cc.LastGrantedAt.UTC().Format(time.RFC3339),
			})
		}
		c.JSON(http.StatusOK, gin.H{
			"consents":                      out,
			"access_token_lifetime_seconds": int64(deps.AccessTokenLifetime / time.Second),
		})
	}
}

// meConsentNotFound is the one 404 of DELETE: an application the caller holds
// no active consent for, another user's, an unknown or a deleted one.
func meConsentNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "You have not given this application access."})
}

// HandleRevokeOwnConsent serves DELETE /api/v1/me/consents/:client_id. The
// refresh tokens are ended BEFORE the consent is revoked: if ending them
// fails, the consent stays listed and a retry finishes the work, instead of
// a retry answering 404 over tokens still live.
func HandleRevokeOwnConsent(deps MeConsentsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := meConsentCaller(c, deps)
		if user == nil {
			return
		}
		clientID := c.Param("client_id")
		ctx := c.Request.Context()
		held, err := deps.Consents.HasActiveForClient(ctx, user.ID, clientID)
		if err != nil && !errors.Is(err, service.ErrConsentInvalidInput) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		if !held {
			meConsentNotFound(c)
			return
		}
		// A deleted application is absent here as in the list: the same 404
		// as an unknown client_id, and nothing is revoked (OSS-0913-A-REVIEW F2).
		client, err := deps.Clients.GetClientByClientID(ctx, clientID)
		if errors.Is(err, domain.ErrClientNotFound) || (err == nil && client == nil) {
			meConsentNotFound(c)
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error"})
			return
		}
		refreshCount, err := deps.Refresh.RevokeAllForUserClient(ctx, user.ID, clientID)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
			return
		}
		consentRows, err := deps.Consents.RevokeClient(ctx, user.ID, clientID)
		if err != nil && !errors.Is(err, service.ErrConsentNotFound) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
			return
		}
		c.Status(http.StatusNoContent)
		_ = deps.Audit.Record(ctx, audit.Event{
			Action:         string(domain.AuditSelfConsentRevoked),
			Outcome:        "success",
			ActorID:        user.ID,
			ActorType:      "user",
			ActorRole:      string(user.Role),
			OrganizationID: user.OrganizationID,
			SubjectID:      user.ID,
			SubjectType:    "user",
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"client_id":                    clientID,
				"consent_rows_revoked":         consentRows,
				"refresh_tokens_revoked_count": refreshCount,
			},
		})
	}
}
