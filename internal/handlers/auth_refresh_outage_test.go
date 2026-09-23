package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Owner decision D2 (PLAN-C-CLOSE, 2026-09-23), unit proof: the JSON
// refresh answers a session-store outage exactly as the browser refresh
// does — 503 refresh_unavailable — not the generic 500 internal_error, and
// rotates nothing. Status lookups failing is the measured outage shape
// (ErrUserSessionUnavailable).
func TestSessionRefresh_D2_StoreOutageIs503RefreshUnavailable(t *testing.T) {
	_, repo, _, issued := browserRefreshFixture(t)
	repo.statusErr = errors.New("fixture store unavailable")
	before := *repo.byID[issued.Session.ID].TokenValidatorHash
	e := gin.New()
	e.POST("/refresh", HandleSessionRefresh(AuthSessionsHandlerDeps{UserSession: service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})}))
	body, _ := json.Marshal(map[string]string{"refresh_token": issued.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"refresh_unavailable"`) {
		t.Fatalf("JSON refresh during a store outage: %d %q, want 503 refresh_unavailable", rec.Code, rec.Body.String())
	}
	if after := *repo.byID[issued.Session.ID].TokenValidatorHash; after != before {
		t.Fatal("an outage must not rotate the refresh credential")
	}
}
