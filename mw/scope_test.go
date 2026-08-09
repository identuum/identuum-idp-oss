package mw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/types"
	"github.com/stretchr/testify/assert"
)

func setPrincipal(p types.Principal) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(domain.CtxKeyPrincipal, p)
		c.Next()
	}
}

func TestRequireScopesAny(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		principal      types.Principal
		requiredScopes []string
		expectedStatus int
		expectChecked  bool
	}{
		{
			name: "Client with exact scope",
			principal: types.Principal{
				Kind:     types.PrincipalKindClient,
				UserID:   uuid.Must(uuid.NewV7()),
				OrgID:    uuid.Must(uuid.NewV7()),
				ScopeSet: map[string]struct{}{domain.ScopeM2MRead: {}},
			},
			requiredScopes: []string{domain.ScopeM2MRead},
			expectedStatus: http.StatusOK,
			expectChecked:  true,
		},
		{
			name: "Client with partial scope match (OR logic)",
			principal: types.Principal{
				Kind:     types.PrincipalKindClient,
				ScopeSet: map[string]struct{}{domain.ScopeM2MRead: {}},
			},
			requiredScopes: []string{domain.ScopeM2MRead, domain.ScopeM2MUpdate},
			expectedStatus: http.StatusOK,
			expectChecked:  true,
		},
		{
			name: "Client without required scope",
			principal: types.Principal{
				Kind:     types.PrincipalKindClient,
				ScopeSet: map[string]struct{}{"other:scope": {}},
			},
			requiredScopes: []string{domain.ScopeM2MRead},
			expectedStatus: http.StatusForbidden,
			expectChecked:  true, // Checked but failed
		},
		{
			name: "Client with NO scopes",
			principal: types.Principal{
				Kind:     types.PrincipalKindClient,
				ScopeSet: map[string]struct{}{},
			},
			requiredScopes: []string{domain.ScopeM2MRead},
			expectedStatus: http.StatusForbidden,
			expectChecked:  true, // Checked but failed
		},
		{
			name: "User Principal (Bypass)",
			principal: types.Principal{
				Kind:   types.PrincipalKindUser,
				UserID: uuid.Must(uuid.NewV7()),
			},
			requiredScopes: []string{domain.ScopeM2MRead},
			expectedStatus: http.StatusOK,
			expectChecked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := gin.New()

			// Chain
			r.GET("/",
				setPrincipal(tt.principal),
				RequireScopesAny(tt.requiredScopes...),
				func(c *gin.Context) {
					// Verify flag inside the handler if it reached here
					if tt.expectChecked {
						assert.True(t, c.GetBool(domain.CtxKeyScopesChecked), "scopes_checked should be true")
					} else if tt.expectedStatus == http.StatusOK {
						// For User Bypass, it should NOT be true
						assert.False(t, c.GetBool(domain.CtxKeyScopesChecked), "scopes_checked should be false")
					}
					c.Status(http.StatusOK)
				},
			)

			req, _ := http.NewRequest("GET", "/", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestDenyM2MClients(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		principal       types.Principal
		hasPrincipal    bool
		expectedStatus  int
		handlerExecuted bool
	}{
		{
			name: "M2M client is denied before handler runs",
			principal: types.Principal{
				Kind: types.PrincipalKindClient,
			},
			hasPrincipal:    true,
			expectedStatus:  http.StatusForbidden,
			handlerExecuted: false, // handler must NOT run
		},
		{
			name: "User principal passes through to handler",
			principal: types.Principal{
				Kind:   types.PrincipalKindUser,
				UserID: uuid.Must(uuid.NewV7()),
			},
			hasPrincipal:    true,
			expectedStatus:  http.StatusOK,
			handlerExecuted: true,
		},
		{
			name:            "No principal in context passes through",
			hasPrincipal:    false,
			expectedStatus:  http.StatusOK,
			handlerExecuted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := gin.New()

			handlerRan := false
			r.GET("/",
				func(c *gin.Context) {
					if tt.hasPrincipal {
						c.Set(domain.CtxKeyPrincipal, tt.principal)
					}
					c.Next()
				},
				DenyM2MClients(),
				func(c *gin.Context) {
					// This handler must NOT execute for M2M clients
					handlerRan = true
					c.Status(http.StatusOK)
				},
			)

			req, _ := http.NewRequest("GET", "/", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.handlerExecuted, handlerRan,
				"handler execution state mismatch: expected=%v got=%v", tt.handlerExecuted, handlerRan)
		})
	}
}
