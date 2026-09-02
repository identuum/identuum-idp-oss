// Package mw hosts the OSS-safe Gin middleware seam.
//
// As of this slice, the package exposes the smallest credible
// authorization guard: middleware that checks a `*domain.Principal`
// already attached to the gin.Context. The middleware does NOT
// populate the principal — that is a future slice (real session/OIDC
// bearer validation) and lives in OSS bootstrap/CE later.
//
// Composition contract:
//
//  1. Some upstream layer (CE wiring, reverse proxy with mTLS, or a
//     future OSS auth middleware) calls mw.SetPrincipal(c, p).
//  2. Route groups that need authorization mount
//     mw.RequireAuthenticated() / mw.RequireSiteAdmin() /
//     mw.RequireScopesAny(...).
//  3. If no principal is in context, the guard returns 401.
//     If the principal is wrong, it returns 403.
//
// Tests can use mw.InjectPrincipalForTest(p) to plant a principal
// in the request context without standing up the full auth chain.
//
// This package does NOT:
//   - parse bearer tokens
//   - parse cookies
//   - validate sessions
//   - call any external auth service
//   - log credentials, tokens, or principal email addresses
package mw

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// principalContextKey is the gin.Context key under which the
// authenticated principal is stored. Kept unexported so callers go
// through SetPrincipal/PrincipalFromContext.
const principalContextKey = "identuum-oss-principal"

// SetPrincipal attaches p to c. A nil p clears the previously stored
// principal — middleware further down the chain will then treat the
// request as unauthenticated.
func SetPrincipal(c *gin.Context, p *domain.Principal) {
	if p == nil {
		c.Set(principalContextKey, (*domain.Principal)(nil))
		return
	}
	c.Set(principalContextKey, p)
}

// PrincipalFromContext returns the stored principal and a presence
// flag. If the value at the key was explicitly set to nil, the flag
// is false (treat as unauthenticated).
func PrincipalFromContext(c *gin.Context) (*domain.Principal, bool) {
	v, ok := c.Get(principalContextKey)
	if !ok {
		return nil, false
	}
	p, ok := v.(*domain.Principal)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

// RequireAuthenticated short-circuits with 401 when no principal is
// attached to the request context. Mount before any route group
// that requires the caller to have proven their identity, even when
// no specific role/scope is needed.
func RequireAuthenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := PrincipalFromContext(c); !ok {
			respondUnauthenticated(c)
			return
		}
		c.Next()
	}
}

// RequireSiteAdmin enforces the principal carries the site-admin
// role. Falls through to 401 when no principal is present, 403 when
// the principal exists but is not a site admin.
func RequireSiteAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		if !p.IsSiteAdmin() {
			respondForbidden(c)
			return
		}
		c.Next()
	}
}

// RequireScopesAny enforces the principal's `Scope` claim contains
// AT LEAST ONE of the supplied scopes. The principal's Scope is the
// OAuth-style whitespace-separated string used in monolith JWT
// claims; this middleware splits on whitespace and matches exactly.
//
// Behaviour matrix:
//   - no principal           → 401
//   - principal with no overlap → 403
//   - principal with overlap → next
//   - empty scopes argument  → next (no-op; pass-through guard)
func RequireScopesAny(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(scopes) == 0 {
			c.Next()
			return
		}
		p, ok := PrincipalFromContext(c)
		if !ok {
			respondUnauthenticated(c)
			return
		}
		held := make(map[string]struct{}, 8)
		for _, s := range strings.Fields(p.Scope) {
			held[s] = struct{}{}
		}
		for _, need := range scopes {
			if _, ok := held[need]; ok {
				c.Next()
				return
			}
		}
		respondForbidden(c)
	}
}

// InjectPrincipalForTest returns a middleware that plants p into the
// request context. Intended for tests that need to bypass the full
// auth chain while still exercising downstream RequireX guards. NOT
// for production use; the function name spells out its scope.
//
// Passing nil is a programming bug: prefer not mounting the
// middleware at all if the test wants the unauthenticated path.
func InjectPrincipalForTest(p *domain.Principal) gin.HandlerFunc {
	if p == nil {
		panic("mw: InjectPrincipalForTest called with nil principal — use no middleware to test the unauthenticated path")
	}
	return func(c *gin.Context) {
		SetPrincipal(c, p)
		c.Next()
	}
}

// respondUnauthenticated is the guards' 401: no credential reached the
// route (AUTH-503: every 401 names its verdict; see auth_verdict.go).
func respondUnauthenticated(c *gin.Context) {
	RespondUnauthenticatedReason(c, ReasonNoCredential)
}

func respondForbidden(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error": "forbidden",
	})
}
