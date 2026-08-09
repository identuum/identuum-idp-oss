package mw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/identuum/identuum-idp-oss/types"
)

// DenyM2MClients blocks M2M service accounts (PrincipalKindClient) from accessing
// endpoints that are strictly for interactive user sessions.
// It aborts with 403 BEFORE the handler runs, ensuring no response body is ever written.
//
// Use this instead of RequireScopesAny for endpoints where M2M access is
// architecturally prohibited (e.g. logout, MFA setup, password change, profile).
//
// Security (CRIT-2): This replaces the defunct ClientDenyByDefault which called c.Next()
// first, allowing the handler to write a response body before the 403 could fire.
// Gin silently drops subsequent WriteHeader calls on an already-committed response,
// making ClientDenyByDefault a no-op in practice.
func DenyM2MClients() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get(domain.CtxKeyPrincipal)
		if !exists {
			c.Next()
			return
		}
		principal, ok := val.(types.Principal)
		if !ok {
			c.Next()
			return
		}
		if principal.Kind == types.PrincipalKindClient {
			requestID := c.GetString(RequestIDKey)
			logger.Warning.WithFields(map[string]any{
				domain.CtxKeyRequestID: requestID,
				"path":                 c.Request.URL.Path,
				"method":               c.Request.Method,
			}).Print("DenyM2MClients: service account attempted to access a user-only endpoint")

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "this endpoint is not accessible to service accounts",
			})
			return
		}
		c.Next()
	}
}

// RequireScopesAny checks if the client has AT LEAST ONE of the required scopes.
// Also validates that scopes are not empty/whitespace-only.
// If passed, sets `scopes_checked=true`.
func RequireScopesAny(required ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get(domain.CtxKeyPrincipal)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "message": "unauthorized"})
			return
		}
		principal := val.(types.Principal)

		// User Bypass (RBAC) - Scope checks apply only to Clients
		if principal.Kind != types.PrincipalKindClient {
			c.Next()
			return
		}

		// Client Checks
		c.Set(domain.CtxKeyScopesChecked, true) // Mark as checked regardless of outcome

		hasScope := domain.HasAnyScope(principal.ScopeSet, required)
		if !hasScope {
			requestID := c.GetString(RequestIDKey)
			logger.Warning.WithFields(map[string]any{
				domain.CtxKeyRequestID: requestID,
				"required":             required,
				"held":                 getScopeKeys(principal.ScopeSet),
			}).Print("RequireScopesAny: Missing required scope")

			// Strict: Check for empty/whitespace only
			if len(principal.ScopeSet) == 0 {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "message": "insufficient scopes (none)"})
				return
			}

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": fmt.Sprintf("missing required scope: %s", strings.Join(required, " or ")),
			})
			return
		}

		// Success
		c.Next()
	}
}

func getScopeKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
