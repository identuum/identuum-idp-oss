package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// TestNewOSSEngine_AdvancedDCRRoutesNotRegistered pins the DCR
// surface-scoping contract (integrity-audit F6/C1, see
// docs/audit/changelog/dcr-surface-scoping.md): the advanced-DCR
// routes (initial-access-token management + RFC 7592 client
// management) are Enterprise/CE-only and must NOT register on the OSS
// engine EVEN WHEN the backing services are supplied — the mounts were
// removed, not merely nil-gated. Before the scoping slice, the deps
// below would have registered all six routes.
//
// The zero-value service pointers are never dereferenced: the
// assertion is purely about route REGISTRATION (gin's route table).
func TestNewOSSEngine_AdvancedDCRRoutesNotRegistered(t *testing.T) {
	clientRepo := newMinimalClientRepo()
	deps := OSSRouterDeps{
		ClientService:                     service.NewClientService(nil, clientRepo),
		DCRInitialAccessTokenService:      &service.DCRInitialAccessTokenService{},
		DCRRegistrationAccessTokenService: &service.DCRRegistrationAccessTokenService{},
		DCRRegistrationBaseURL:            "https://idp.test",
	}
	e := NewOSSEngine(deps)

	// Registration-level assertion via gin's route table.
	var kept bool
	for _, r := range e.Routes() {
		if strings.HasPrefix(r.Path, "/api/v1/dcr/initial-access-tokens") {
			t.Errorf("advanced-DCR IAT route registered on OSS engine: %s %s (must be CE-only)", r.Method, r.Path)
		}
		if strings.HasPrefix(r.Path, "/api/v1/oauth/register/") {
			t.Errorf("RFC 7592 management route registered on OSS engine: %s %s (must be CE-only)", r.Method, r.Path)
		}
		if r.Method == http.MethodPost && r.Path == "/api/v1/oauth/register" {
			kept = true
		}
	}
	if !kept {
		t.Error("kept basic DCR route POST /api/v1/oauth/register is no longer registered — scoping removed too much")
	}

	// Wire-level confirmation: the six removed paths 404 through the
	// assembled engine, while the kept route is routed (its handler
	// responds — anything but 404 proves registration; an unauthenticated
	// request is rejected by the handler/auth chain, not the router).
	removed := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/dcr/initial-access-tokens"},
		{http.MethodPost, "/api/v1/dcr/initial-access-tokens"},
		{http.MethodPost, "/api/v1/dcr/initial-access-tokens/abc/revoke"},
		{http.MethodGet, "/api/v1/oauth/register/abc"},
		{http.MethodPut, "/api/v1/oauth/register/abc"},
		{http.MethodDelete, "/api/v1/oauth/register/abc"},
	}
	for _, tc := range removed {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404 (removed advanced-DCR route)", tc.method, tc.path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/oauth/register", nil))
	if rec.Code == http.StatusNotFound {
		t.Errorf("POST /api/v1/oauth/register returned 404 — the kept basic DCR route must remain served")
	}
}
