package api

// registration_routes_test.go — replaces D-015's absence tripwires
// (TestNewOSSEngine_PublicRegistrationRoutesAbsent and
// TestNewOSSEngine_RegistrationApprovalRoutesAbsent): since D-021 OSS mounts
// self-registration, gated by the instance switch and the organization's
// AllowPublicRegistration. Pinned here: nothing is mounted without the
// service; with it, the public routes answer, and an instance that is off
// answers every organization as closed with the same bodies the
// integration test (internal/e2e/self_registration_http_test.go) proves for
// unknown and idp_only organizations; no other registration path exists.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type offRegistrationRepo struct{}

func (offRegistrationRepo) InstanceEnabled(context.Context) (bool, error) { return false, nil }
func (offRegistrationRepo) SetInstanceEnabled(context.Context, bool) error { return nil }
func (offRegistrationRepo) OrgSettings(context.Context, uuid.UUID) (*domain.OrgRegistrationSettings, error) {
	return &domain.OrgRegistrationSettings{Allow: true}, nil
}
func (offRegistrationRepo) UpdateOrgSettings(context.Context, uuid.UUID, domain.OrgRegistrationSettings) error {
	return nil
}
func (offRegistrationRepo) SetUserState(context.Context, uuid.UUID, string) error { return nil }
func (offRegistrationRepo) UserState(context.Context, uuid.UUID) (string, bool, error) {
	return "", false, nil
}
func (offRegistrationRepo) ListPending(context.Context, uuid.UUID) ([]domain.PendingRegistration, error) {
	return nil, nil
}

func serve(e http.Handler, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestNewOSSEngine_SelfRegistrationRoutes(t *testing.T) {
	if st, _ := serve(NewOSSEngine(OSSRouterDeps{}), http.MethodPost, "/api/v1/auth/register/acme", `{}`); st != http.StatusNotFound {
		t.Fatalf("without the registration service POST register = %d; want 404 (nothing mounted)", st)
	}
	e := NewOSSEngine(OSSRouterDeps{RegistrationService: service.NewRegistrationService(service.RegistrationServiceConfig{Repo: offRegistrationRepo{}})})
	if st, b := serve(e, http.MethodGet, "/api/v1/auth/register/acme", ""); st != http.StatusOK || b != `{"open":false}` {
		t.Fatalf("GET register with the instance off = %d %s; want 200 {\"open\":false}", st, b)
	}
	if st, b := serve(e, http.MethodPost, "/api/v1/auth/register/acme", `{"email":"a@acme.test","password":"short"}`); st != http.StatusAccepted || b != `{"accepted":true}` {
		t.Fatalf("POST register with the instance off = %d %s; want the one 202 (no policy check on a closed org)", st, b)
	}
	for _, p := range []string{"/api/v1/auth/register", "/api/v1/auth/signup", "/api/v1/users/register", "/api/v1/register", "/api/v1/signup", "/api/v1/users/pending/approve", "/api/v1/registrations/approve"} {
		if st, _ := serve(e, http.MethodPost, p, `{}`); st != http.StatusNotFound {
			t.Errorf("POST %s = %d; want 404: the per-organization path is the only sign-up route", p, st)
		}
	}
}
