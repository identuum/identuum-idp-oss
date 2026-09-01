package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// siteAdminPrincipal returns a fresh *domain.Principal carrying the
// site-admin role. Each test that needs an authorized caller calls
// this so the principal IDs don't leak between cases.
func siteAdminPrincipal() *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "site-admin@example.test",
		Role:           domain.RoleSiteAdmin,
	}
}

// fakeKeyRepo implements repository.KeyRepository just enough for
// the handler tests. Methods not exercised by tests return errors
// or panic so accidental new dependencies surface as test failures.
type fakeKeyRepo struct {
	active      []domain.SigningKey
	all         []domain.SigningKey
	deleted     int
	getByKID    func(string) (*domain.SigningKey, error)
	createCalls int
	rotateCalls int
	depCalls    int
	delErr      error
}

func (f *fakeKeyRepo) GetActiveSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return f.active, nil
}
func (f *fakeKeyRepo) GetAllSigningKeys(_ context.Context) ([]domain.SigningKey, error) {
	return f.all, nil
}
func (f *fakeKeyRepo) GetSigningKeyByKID(_ context.Context, kid string) (*domain.SigningKey, error) {
	if f.getByKID != nil {
		return f.getByKID(kid)
	}
	return nil, errors.New("not found")
}
func (f *fakeKeyRepo) CreateSigningKey(_ context.Context, k *domain.SigningKey) error {
	f.createCalls++
	f.all = append(f.all, *k)
	return nil
}
func (f *fakeKeyRepo) ActivateSigningKey(_ context.Context, _ string) error { return nil }
func (f *fakeKeyRepo) RotateSigningKey(_ context.Context, _, _ string, _ *time.Time) error {
	f.rotateCalls++
	return nil
}
func (f *fakeKeyRepo) DeprecateSigningKey(_ context.Context, _ string, _ time.Time) error {
	f.depCalls++
	return nil
}
func (f *fakeKeyRepo) DeleteExpiredKeys(_ context.Context) (int, error) {
	if f.delErr != nil {
		return 0, f.delErr
	}
	return f.deleted, nil
}

var _ repository.KeyRepository = (*fakeKeyRepo)(nil)

func newTestEngine(t *testing.T, repo *fakeKeyRepo, rec *audit.Recorder) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Inject a site-admin principal so the RequireSiteAdmin guard
	// inside RegisterKeysRoutes allows the request through.
	r.Use(mw.InjectPrincipalForTest(siteAdminPrincipal()))
	deps := KeysHandlerDeps{
		KeyService: service.NewKeyService(repo),
		Audit:      rec,
	}
	if rec == nil {
		deps.Audit = audit.NoopService{}
	}
	RegisterKeysRoutes(r, deps)
	return r
}

// newTestEngineNoPrincipal builds an engine WITHOUT the
// inject-principal middleware so tests can exercise the 401 path
// directly.
func newTestEngineNoPrincipal(t *testing.T, repo *fakeKeyRepo) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	deps := KeysHandlerDeps{
		KeyService: service.NewKeyService(repo),
		Audit:      audit.NoopService{},
	}
	RegisterKeysRoutes(r, deps)
	return r
}

// newTestEngineWithPrincipal lets a test pick the principal — used
// for the 403 (non-site-admin) coverage.
func newTestEngineWithPrincipal(t *testing.T, repo *fakeKeyRepo, p *domain.Principal) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	deps := KeysHandlerDeps{
		KeyService: service.NewKeyService(repo),
		Audit:      audit.NoopService{},
	}
	RegisterKeysRoutes(r, deps)
	return r
}

func TestListSigningKeys_OmitsPrivateMaterial(t *testing.T) {
	repo := &fakeKeyRepo{
		all: []domain.SigningKey{
			{
				ID:         uuid.New(),
				KID:        "kid-1",
				Algorithm:  domain.KeyAlgorithmEdDSA,
				PublicKey:  "PUBLIC-MATERIAL",
				PrivateKey: "PRIVATE-SHOULD-NEVER-LEAK",
				State:      domain.KeyStateActive,
				CreatedAt:  time.Now().UTC(),
			},
		},
	}
	r := newTestEngine(t, repo, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"public_key":"PUBLIC-MATERIAL"`) {
		t.Errorf("body missing expected public_key field; got %q", body)
	}
	if strings.Contains(body, "PRIVATE-SHOULD-NEVER-LEAK") {
		t.Errorf("body leaked private key material: %q", body)
	}
	if strings.Contains(body, `"private_key"`) {
		t.Errorf("body contains private_key field name: %q", body)
	}
}

// THE-PKCE-DECISION: RS256 generation is now ALLOWED — a real, testing-only
// capability requested explicitly by an operator. The response must carry the
// public key only. The never-DEFAULT posture is pinned in
// internal/service (selectIDTokenSigningKey) and auth (primary selection).
func TestGenerateSigningKey_AllowsRS256(t *testing.T) {
	repo := &fakeKeyRepo{}
	r := newTestEngine(t, repo, nil)

	body, _ := json.Marshal(map[string]string{"algorithm": "RS256"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	if repo.createCalls != 1 {
		t.Errorf("CreateSigningKey calls = %d, want 1", repo.createCalls)
	}
	respBody := rec.Body.String()
	if !strings.Contains(respBody, `"algorithm":"RS256"`) {
		t.Errorf("body missing RS256 algorithm; got %q", respBody)
	}
	if strings.Contains(respBody, `"private_key"`) || strings.Contains(respBody, "BEGIN PRIVATE KEY") {
		t.Errorf("body leaked private key material: %q", respBody)
	}
}

// The allow-list still refuses algorithms outside {EdDSA, ES256, RS256}.
func TestGenerateSigningKey_RejectsUnknownAlgorithm(t *testing.T) {
	repo := &fakeKeyRepo{}
	r := newTestEngine(t, repo, nil)

	body, _ := json.Marshal(map[string]string{"algorithm": "HS256"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	if repo.createCalls != 0 {
		t.Errorf("CreateSigningKey was called for an HS256 request (%d times)", repo.createCalls)
	}
}

func TestGenerateSigningKey_EdDSAEmitsAudit(t *testing.T) {
	repo := &fakeKeyRepo{}
	rec := &audit.Recorder{}
	r := newTestEngine(t, repo, rec)

	body, _ := json.Marshal(map[string]string{"algorithm": "EdDSA"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", w.Code, w.Body.String())
	}
	if repo.createCalls != 1 {
		t.Errorf("CreateSigningKey calls = %d, want 1", repo.createCalls)
	}
	if rec.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", rec.Len())
	}
	event := rec.Events()[0]
	if event.Action != "key.generated" || event.Outcome != "success" {
		t.Errorf("audit event mismatch: %+v", event)
	}
	for k := range event.Metadata {
		// No metadata key should suggest key material exposure.
		if k == "private_key" || k == "public_key" || k == "d" {
			t.Errorf("audit metadata contains key-material-like key %q", k)
		}
	}
}

func TestRotateSigningKey_AuditEmittedNoKeyMaterial(t *testing.T) {
	repo := &fakeKeyRepo{}
	rec := &audit.Recorder{}
	r := newTestEngine(t, repo, rec)

	body, _ := json.Marshal(map[string]any{
		"old_kid":        "kid-old",
		"new_kid":        "kid-new",
		"deprecate_days": 30,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if repo.rotateCalls != 1 {
		t.Errorf("RotateSigningKey calls = %d, want 1", repo.rotateCalls)
	}
	if rec.Len() != 1 || rec.Events()[0].Action != "key.rotated" {
		t.Errorf("audit recorder did not capture key.rotated: %+v", rec.Events())
	}
}

func TestDeleteExpiredKeys_RepoErrorIs500(t *testing.T) {
	repo := &fakeKeyRepo{delErr: errors.New("db down")}
	r := newTestEngine(t, repo, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/expired", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("body leaks internal error detail: %q", rec.Body.String())
	}
}

func TestDeleteExpiredKeys_Happy(t *testing.T) {
	repo := &fakeKeyRepo{deleted: 3}
	r := newTestEngine(t, repo, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/expired", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"deleted":3`) {
		t.Errorf("body missing deleted count; got %q", rec.Body.String())
	}
}

func TestReloadSigningKey_NotImplemented(t *testing.T) {
	repo := &fakeKeyRepo{}
	r := newTestEngine(t, repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/reload", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "KeyManager not yet relocated") {
		t.Errorf("body missing not-implemented explanation; got %q", rec.Body.String())
	}
}

// TestKeysGuard_UnauthenticatedReturns401 verifies the keys route
// group refuses anonymous requests. No principal in context →
// 401 + {"error":"unauthorized"}.
func TestKeysGuard_UnauthenticatedReturns401(t *testing.T) {
	repo := &fakeKeyRepo{}
	r := newTestEngineNoPrincipal(t, repo)
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/keys"},
		{http.MethodPost, "/api/v1/keys/generate"},
		{http.MethodPost, "/api/v1/keys/rotate"},
		{http.MethodPost, "/api/v1/keys/deprecate"},
		{http.MethodDelete, "/api/v1/keys/expired"},
		{http.MethodPost, "/api/v1/keys/reload"},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status = %d, want 401", c.method, c.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"unauthorized"`) {
			t.Errorf("%s %s body does not contain unauthorized marker: %q", c.method, c.path, rec.Body.String())
		}
	}
}

// TestKeysGuard_NonSiteAdminReturns403 verifies that an
// authenticated-but-not-site-admin principal is refused. The
// principal is treated as authenticated (mw.SetPrincipal was
// called) but its role does not match the guard.
func TestKeysGuard_NonSiteAdminReturns403(t *testing.T) {
	repo := &fakeKeyRepo{}
	orgUser := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "org-user@example.test",
		Role:           domain.RoleOrgUser,
	}
	r := newTestEngineWithPrincipal(t, repo, orgUser)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("non-site-admin GET /api/v1/keys status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"forbidden"`) {
		t.Errorf("body missing forbidden marker: %q", rec.Body.String())
	}
}

// TestKeysGuard_OrgAdminAlsoReturns403 documents that the
// org-admin role is NOT enough — site-admin is the only role that
// reaches the keys handlers.
func TestKeysGuard_OrgAdminAlsoReturns403(t *testing.T) {
	repo := &fakeKeyRepo{}
	orgAdmin := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "org-admin@example.test",
		Role:           domain.RoleOrgAdmin,
	}
	r := newTestEngineWithPrincipal(t, repo, orgAdmin)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("org-admin GET /api/v1/keys status = %d, want 403", rec.Code)
	}
}

// TestRegisterKeysRoutes_NilKeyServiceFailsClosed confirms the P-018
// conversion: registering keys routes without a backing service no longer
// panics (which would kill the process) — it records a fatal startup fault
// naming the keys-routes component and mounts a service-missing fallback,
// so the group's routes refuse cleanly with 503 instead of crashing.
func TestRegisterKeysRoutes_NilKeyServiceFailsClosed(t *testing.T) {
	report := lifecycle.NewStartupReport()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("RegisterKeysRoutes(nil KeyService) panicked: %v", rec)
			}
		}()
		RegisterKeysRoutes(r, KeysHandlerDeps{KeyService: nil, StartupReport: report})
	}()

	if !report.HasFatal() {
		t.Fatalf("nil KeyService must record a fatal fault")
	}
	named := false
	for _, f := range report.Faults() {
		if f.Component == "keys-routes" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name keys-routes; got %+v", report.Faults())
	}

	// The group's routes return the service-missing 503 response, not a crash.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /api/v1/keys (no service) status = %d, want 503", rec.Code)
	}
	t.Logf("EVIDENCE keys nil-service: no panic; faults=%+v; GET /api/v1/keys → %d", report.Faults(), rec.Code)
}
