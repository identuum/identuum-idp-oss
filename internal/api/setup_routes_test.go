package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/setup"
)

// fakeSetupService is a controllable fake satisfying the SetupService
// interface. We pin specific (response, error) pairs per method so each
// route test can drive a precise branch.
type fakeSetupService struct {
	statusView  *setup.StatusView
	statusErr   error
	verifyErr   error
	completeOut *setup.CompleteOutput
	completeErr error

	lastCompleteInput setup.CompleteInput
	lastDataDir       string
}

func (f *fakeSetupService) Status(_ context.Context) (*setup.StatusView, error) {
	return f.statusView, f.statusErr
}
func (f *fakeSetupService) VerifyToken(_ context.Context, _ string) error {
	return f.verifyErr
}
func (f *fakeSetupService) Complete(_ context.Context, dataDir string, in setup.CompleteInput) (*setup.CompleteOutput, error) {
	f.lastCompleteInput = in
	f.lastDataDir = dataDir
	return f.completeOut, f.completeErr
}

// newEngineWithFake builds the OSS engine wired with the fake. The
// public route surface is unchanged; only the /api/setup/* group sees
// the fake.
func newEngineWithFake(fake *fakeSetupService) http.Handler {
	deps := OSSRouterDeps{
		Version:      "test-version 0.0.0",
		SetupService: nil, // we mount the routes directly below to bypass the *setup.Service field
	}
	e := NewOSSEngine(deps)
	RegisterSetupRoutes(e, SetupRoutesDeps{Service: fake, DataDir: "/tmp/test-data"})
	return e
}

func TestSetup_Status_OK(t *testing.T) {
	fake := &fakeSetupService{
		statusView: &setup.StatusView{
			State:                   domain.SetupStatusRequired,
			SetupComplete:           false,
			SetupTokenRequired:      true,
			Product:                 setup.ProductOSS,
			Distribution:            setup.DistributionOSS,
			Issuer:                  "http://localhost:7113",
			FirstSigningKeyExists:   false,
			SiteAdminExists:         false,
			FirstOrganizationExists: false,
			NextAction:              "Open the setup wizard and submit the first organization, the site administrator credentials, and the setup code from the data-volume file.",
		},
	}
	e := newEngineWithFake(fake)

	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%q", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["state"] != domain.SetupStatusRequired {
		t.Errorf("state = %v; want %s", body["state"], domain.SetupStatusRequired)
	}
	if body["setup_token_required"] != true {
		t.Errorf("setup_token_required = %v; want true", body["setup_token_required"])
	}
	if body["product"] != setup.ProductOSS {
		t.Errorf("product = %v; want %s", body["product"], setup.ProductOSS)
	}
	// No-secrets assertion: confirm no field looks like a token or hash.
	for _, banned := range []string{"setup_token", "token_hash", "password", "private_key"} {
		if _, present := body[banned]; present {
			t.Errorf("status body must not contain %q field; got %v", banned, body)
		}
	}
}

func TestSetup_VerifyToken_NoContentOnMatch(t *testing.T) {
	fake := &fakeSetupService{verifyErr: nil}
	e := newEngineWithFake(fake)

	body, _ := json.Marshal(map[string]string{"setup_token": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/verify-token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d; want 204; body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("204 body should be empty; got %q", rec.Body.String())
	}
}

func TestSetup_VerifyToken_UnauthorizedOnMismatch(t *testing.T) {
	fake := &fakeSetupService{verifyErr: setup.ErrTokenInvalid}
	e := newEngineWithFake(fake)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/verify-token", bytes.NewReader([]byte(`{"setup_token":"wrong"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401; body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "wrong") {
		t.Errorf("response must not echo the candidate token; body=%q", rec.Body.String())
	}
}

func TestSetup_VerifyToken_GoneAfterComplete(t *testing.T) {
	fake := &fakeSetupService{verifyErr: setup.ErrAlreadyComplete}
	e := newEngineWithFake(fake)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/verify-token", bytes.NewReader([]byte(`{"setup_token":"anything"}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Errorf("status = %d; want 410", rec.Code)
	}
}

func TestSetup_VerifyToken_BadJSONIs400(t *testing.T) {
	fake := &fakeSetupService{}
	e := newEngineWithFake(fake)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/verify-token", bytes.NewReader([]byte(`not-json`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestSetup_Complete_OK(t *testing.T) {
	out := &setup.CompleteOutput{
		State:            domain.SetupStatusComplete,
		OrganizationName: "Acme Corp",
		AdminEmail:       "owner@acme.example",
	}
	fake := &fakeSetupService{completeOut: out}
	e := newEngineWithFake(fake)

	reqBody := map[string]string{
		"setup_token":         "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST",
		"organization_name":   "Acme Corp",
		"organization_domain": "acme.example",
		"admin_email":         "owner@acme.example",
		"admin_password":      "very-long-test-password-1234",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "very-long-test-password") {
		t.Errorf("response leaked the admin password: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") {
		t.Errorf("response leaked the setup token: %q", rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["state"] != domain.SetupStatusComplete {
		t.Errorf("state = %v; want %s", got["state"], domain.SetupStatusComplete)
	}
	if got["organization_name"] != "Acme Corp" {
		t.Errorf("organization_name = %v", got["organization_name"])
	}
	if got["admin_email"] != "owner@acme.example" {
		t.Errorf("admin_email = %v", got["admin_email"])
	}

	// Service received the request shape correctly.
	if fake.lastCompleteInput.OrganizationName != "Acme Corp" {
		t.Errorf("service got OrganizationName=%q", fake.lastCompleteInput.OrganizationName)
	}
	if fake.lastCompleteInput.AdminPassword != "very-long-test-password-1234" {
		t.Errorf("service got AdminPassword=%q", fake.lastCompleteInput.AdminPassword)
	}
	if fake.lastDataDir != "/tmp/test-data" {
		t.Errorf("service got dataDir=%q", fake.lastDataDir)
	}
}

func TestSetup_Complete_UnauthorizedOnBadToken(t *testing.T) {
	fake := &fakeSetupService{completeErr: setup.ErrTokenInvalid}
	e := newEngineWithFake(fake)
	body, _ := json.Marshal(map[string]string{
		"setup_token":         "WRONG",
		"organization_name":   "X",
		"organization_domain": "x.example",
		"admin_email":         "a@b.c",
		"admin_password":      "very-long-test-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", rec.Code)
	}
}

func TestSetup_Complete_GoneOnReplay(t *testing.T) {
	fake := &fakeSetupService{completeErr: setup.ErrAlreadyComplete}
	e := newEngineWithFake(fake)
	body, _ := json.Marshal(map[string]string{
		"setup_token":         "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST",
		"organization_name":   "X",
		"organization_domain": "x.example",
		"admin_email":         "a@b.c",
		"admin_password":      "very-long-test-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Errorf("status = %d; want 410", rec.Code)
	}
}

func TestSetup_Complete_BadRequestMissingFields(t *testing.T) {
	fake := &fakeSetupService{}
	e := newEngineWithFake(fake)
	body, _ := json.Marshal(map[string]string{"setup_token": "only-this"})
	req := httptest.NewRequest(http.MethodPost, "/api/setup/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestSetup_NotMountedWhenServiceNil(t *testing.T) {
	// When OSSRouterDeps.SetupService is nil, the routes are NOT
	// registered — the engine returns 404 on those paths.
	e := NewOSSEngine(OSSRouterDeps{Version: "test-version 0.0.0"})
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404 when SetupService is nil", rec.Code)
	}
}
