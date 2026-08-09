package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type fakeOIDCLoginInitiator struct {
	url       string
	err       error
	gotID     uuid.UUID
	gotReturn string
	calls     int
}

func (f *fakeOIDCLoginInitiator) InitiateLogin(_ context.Context, id uuid.UUID, ret string) (string, error) {
	f.calls++
	f.gotID = id
	f.gotReturn = ret
	return f.url, f.err
}

func newOIDCLoginEngine(t *testing.T, init *fakeOIDCLoginInitiator) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOIDCLoginRoutes(r, OIDCLoginHandlerDeps{OIDCLogin: init, Audit: &audit.Recorder{}})
	return r
}

func idpLoginGET(r *gin.Engine, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// Success → 302 to the authorize URL, with the provider id + return_to
// forwarded to the service.
func TestOIDCLoginRoute_RedirectsOnSuccess(t *testing.T) {
	pid := uuid.New()
	init := &fakeOIDCLoginInitiator{url: "https://provider.example/authorize?state=abc"}
	r := newOIDCLoginEngine(t, init)

	rec := idpLoginGET(r, "/api/v1/auth/idp/"+pid.String()+"/login?return_to=/dashboard")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%q", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != init.url {
		t.Errorf("Location = %q, want %q", loc, init.url)
	}
	if init.gotID != pid {
		t.Errorf("service got id %v, want %v", init.gotID, pid)
	}
	if init.gotReturn != "/dashboard" {
		t.Errorf("service got return_to %q, want /dashboard", init.gotReturn)
	}
}

// Error sentinels map to their status codes with no redirect.
func TestOIDCLoginRoute_ErrorStatusMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{service.ErrLoginProviderNotFound, http.StatusNotFound},
		{service.ErrLoginDiscoveryFailed, http.StatusBadGateway},
		{service.ErrLoginStatePersist, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		init := &fakeOIDCLoginInitiator{err: tc.err}
		r := newOIDCLoginEngine(t, init)
		rec := idpLoginGET(r, "/api/v1/auth/idp/"+uuid.New().String()+"/login")
		if rec.Code != tc.want {
			t.Errorf("err %v: status = %d, want %d", tc.err, rec.Code, tc.want)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("err %v: unexpected redirect to %q", tc.err, loc)
		}
	}
}

// A malformed provider id is rejected 400 before the service is called.
func TestOIDCLoginRoute_InvalidProviderID(t *testing.T) {
	init := &fakeOIDCLoginInitiator{url: "https://x"}
	r := newOIDCLoginEngine(t, init)
	rec := idpLoginGET(r, "/api/v1/auth/idp/not-a-uuid/login")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if init.calls != 0 {
		t.Errorf("service called %d times for a malformed id; want 0", init.calls)
	}
}

// Nil service ⇒ the route is not mounted (optional feature).
func TestOIDCLoginRoute_AbsentWhenServiceNil(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterOIDCLoginRoutes(r, OIDCLoginHandlerDeps{})
	rec := idpLoginGET(r, "/api/v1/auth/idp/"+uuid.New().String()+"/login")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route absent when service nil)", rec.Code)
	}
}
