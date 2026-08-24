package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// TestPrincipalForCtx_RefusesWithoutPrincipal pins the RBAC principal gate: a
// request carrying no valid principal is refused (principalForCtx returns
// nil, false), while a request that carries one is accepted (p, true).
// RULE: PRINCIPAL-REQUIRED-1
func TestPrincipalForCtx_RefusesWithoutPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// No principal in context -> refused.
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if p, ok := principalForCtx(c); ok || p != nil {
		t.Errorf("a request with no principal must be refused, got p=%v ok=%v", p, ok)
	}

	// A valid principal -> accepted.
	c2, _ := gin.CreateTestContext(httptest.NewRecorder())
	mw.SetPrincipal(c2, &domain.Principal{Role: domain.RoleOrgUser})
	if p, ok := principalForCtx(c2); !ok || p == nil {
		t.Errorf("a request with a valid principal must be accepted, got p=%v ok=%v", p, ok)
	}
}
