package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// rejectUnauthenticated is the webauthn in-handler guard: it aborts with 401
// unauthorized. It is what the webauthn register/finish/list/delete handlers
// call when no principal is bound.
// RULE: WEBAUTHN-UNAUTH-1
func TestRejectUnauthenticated_Emits401(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	rejectUnauthenticated(c)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("rejectUnauthenticated must emit 401, got %d", w.Code)
	}
}
