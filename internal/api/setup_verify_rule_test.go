package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// verifyRuleSetupSvc is a SetupService whose VerifyToken outcome is controlled;
// Status/Complete are never reached on the verify-token path.
type verifyRuleSetupSvc struct{ verifyErr error }

func (verifyRuleSetupSvc) Status(context.Context) (*setup.StatusView, error) { return nil, nil }
func (s verifyRuleSetupSvc) VerifyToken(context.Context, string) error       { return s.verifyErr }
func (verifyRuleSetupSvc) Complete(context.Context, string, setup.CompleteInput) (*setup.CompleteOutput, error) {
	return nil, nil
}

// POST /api/setup/verify-token maps the setup-token verdict onto the wire: a
// valid token is 204, an invalid token is 401 (setup_token_invalid), and an
// already-completed setup is 410 (setup_already_complete) — an invalid token is
// never accepted as valid.
// RULE: SETUP-VERIFY-1
func TestHandleSetupVerifyToken_MapsVerdicts(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	post := func(verifyErr error) int {
		r := gin.New()
		RegisterSetupRoutes(r, SetupRoutesDeps{Service: verifyRuleSetupSvc{verifyErr: verifyErr}, DataDir: "/tmp/verify-rule"})
		req := httptest.NewRequest(http.MethodPost, "/api/setup/verify-token", strings.NewReader(`{"setup_token":"tok"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if code := post(nil); code != http.StatusNoContent {
		t.Fatalf("a valid setup token must be 204, got %d", code)
	}
	if code := post(setup.ErrTokenInvalid); code != http.StatusUnauthorized {
		t.Errorf("an invalid setup token must be 401, got %d", code)
	}
	if code := post(setup.ErrAlreadyComplete); code != http.StatusGone {
		t.Errorf("an already-complete setup must be 410, got %d", code)
	}
}
