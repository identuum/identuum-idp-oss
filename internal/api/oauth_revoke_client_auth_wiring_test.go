package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// minimalClientRepo is the smallest repository.ClientRepository
// implementation needed to drive the canonical
// service.OAuthClientAuthService through /oauth/revoke. Only
// GetClientByClientID is exercised by the auth path; every other
// method panics so an accidental new dependency surfaces as a test
// failure rather than a silent no-op.
type minimalClientRepo struct {
	mu   sync.Mutex
	rows map[string]*domain.Client
}

func newMinimalClientRepo() *minimalClientRepo {
	return &minimalClientRepo{rows: map[string]*domain.Client{}}
}

func (r *minimalClientRepo) seedConfidential(clientID, plaintextSecret, authMethod string) *domain.Client {
	id := uuid.New()
	orgID := uuid.New()
	c := &domain.Client{
		ID:                      id,
		ClientID:                clientID,
		Name:                    "wiring-test-client",
		IsPublic:                false,
		ClientSecretHash:        crypto.HashSecret(plaintextSecret),
		TokenEndpointAuthMethod: authMethod,
		OrganizationID:          &orgID,
	}
	r.mu.Lock()
	r.rows[clientID] = c
	r.mu.Unlock()
	return c
}

func (r *minimalClientRepo) RegisterClient(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ClientID] = c
	return nil
}
func (r *minimalClientRepo) GetClientByID(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
	return nil, nil
}
func (r *minimalClientRepo) GetClientByClientID(_ context.Context, clientID string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[clientID], nil
}
func (r *minimalClientRepo) Update(_ context.Context, _ *domain.Client) error { return nil }
func (r *minimalClientRepo) Delete(_ context.Context, _ uuid.UUID, _ *uuid.UUID) error {
	return nil
}
func (r *minimalClientRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.Client, int, error) {
	return nil, 0, nil
}
func (r *minimalClientRepo) ListByServiceAccountID(_ context.Context, _, _ uuid.UUID) ([]*domain.Client, error) {
	panic("not used")
}
func (r *minimalClientRepo) SaveConsent(_ context.Context, _ *domain.Consent) error {
	panic("not used")
}
func (r *minimalClientRepo) GetConsent(_ context.Context, _, _ uuid.UUID, _ *uuid.UUID) (*domain.Consent, error) {
	panic("not used")
}

// canonicalClientAuthDeps constructs an OSSRouterDeps wired with
// the production-grade service.OAuthClientAuthService chain
// (mirrors the runtime.go composition at line 469: NewClientService
// → NewOAuthClientAuthService). The verifier is faked so the test
// does not need real JWT material.
func canonicalClientAuthDeps(t *testing.T, clientID, plaintextSecret string, authMethod ...string) (OSSRouterDeps, *audit.Recorder, *service.RecorderSessionRevoker) {
	t.Helper()
	method := ""
	if len(authMethod) > 0 {
		method = authMethod[0]
	}
	clientRepo := newMinimalClientRepo()
	clientRepo.seedConfidential(clientID, plaintextSecret, method)
	clientSvc := service.NewClientService(nil, clientRepo)
	// apiResourceSvc is intentionally nil — the OAuth-client path
	// never falls through to the api-resource branch for the
	// successful seed, so we can keep the fixture minimal.
	oauthClientAuth := service.NewOAuthClientAuthService(nil, clientSvc, nil)

	verifier := &fakeIntrospectionVerifier{
		claims: &service.IntrospectionClaims{
			Sub:      uuid.New().String(),
			ClientID: clientID,
			Jti:      "JTI-CANONICAL-WIRING",
			Exp:      4102444800, // 2100-01-01
		},
	}
	revoker := &service.RecorderSessionRevoker{}
	rec := &audit.Recorder{}
	deps := OSSRouterDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:       revoker,
		OAuthClientAuth:      oauthClientAuth,
		Audit:                rec,
	}
	return deps, rec, revoker
}

func basicAuthHeader(clientID, clientSecret string) string {
	raw := clientID + ":" + clientSecret
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// TestOSSEngine_RevokeAcceptsCanonicalClientSecretBasic pins the
// production wiring: the runtime hands the same
// service.OAuthClientAuthService chain it constructs at
// runtime.go:469 into OSSRouterDeps.OAuthClientAuth, and the
// /oauth/revoke route consumes it via
// mw.RequireOAuthClient(deps.ClientAuth) — NOT
// mw.RequireSiteAdmin(). A valid client_secret_basic credential
// MUST yield the RFC 7009 §2.2 opaque 200 even when no site_admin
// principal is on the request.
func TestOSSEngine_RevokeAcceptsCanonicalClientSecretBasic(t *testing.T) {
	const clientID = "cli-canonical"
	const clientSecret = "SECRET-MUST-NOT-LEAK-CANARY"
	deps, _, revoker := canonicalClientAuthDeps(t, clientID, clientSecret)

	const rawToken = "OPAQUE-TOKEN-CANONICAL-WIRING"
	engine := NewOSSEngine(deps)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader("token="+rawToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuthHeader(clientID, clientSecret))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (canonical client auth must admit valid creds); body=%q", w.Code, w.Body.String())
	}
	if len(revoker.Calls()) != 1 {
		t.Errorf("session revoker calls = %d, want 1 (handler proceeded past client-auth gate)", len(revoker.Calls()))
	}
	body := w.Body.String()
	if strings.Contains(body, clientSecret) {
		t.Errorf("revoke response leaked client_secret: %q", body)
	}
	if strings.Contains(body, rawToken) {
		t.Errorf("revoke response leaked raw token: %q", body)
	}
	if strings.Contains(body, "JTI-CANONICAL-WIRING") {
		t.Errorf("revoke response leaked jti: %q", body)
	}
}

// TestOSSEngine_RevokeAcceptsCanonicalClientSecretPost mirrors the
// _Basic test but uses client_secret_post (credentials in the form
// body). Both branches of mw.RequireOAuthClient must traverse the
// same wired OAuthClientAuthService.
func TestOSSEngine_RevokeAcceptsCanonicalClientSecretPost(t *testing.T) {
	const clientID = "cli-canonical-post"
	const clientSecret = "POST-SECRET-CANARY"
	deps, _, _ := canonicalClientAuthDeps(t, clientID, clientSecret, service.ClientAuthMethodPost)

	form := "token=ANY&client_id=" + clientID + "&client_secret=" + clientSecret
	w := postRevoke(t, deps, form)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (client_secret_post must traverse canonical auth)", w.Code)
	}
	if strings.Contains(w.Body.String(), clientSecret) {
		t.Errorf("revoke response leaked client_secret: %q", w.Body.String())
	}
}

// TestOSSEngine_RevokeRejectsWrongClientSecretWithInvalidClient
// pins the failure branch: when the canonical auth chain rejects
// the credential the route MUST return 401 invalid_client per RFC
// 6749 §5.2 / RFC 7009 §2.1 — NOT 200 (which would leak the secret
// to a credential-stuffing attacker) and NOT 403 (which would tell
// the attacker the client_id is real). The response body MUST be
// opaque; in particular it must not include the supplied secret.
func TestOSSEngine_RevokeRejectsWrongClientSecretWithInvalidClient(t *testing.T) {
	const clientID = "cli-canonical-reject"
	const realSecret = "REAL-SECRET-CANARY"
	const wrongSecret = "WRONG-GUESS-CANARY"
	deps, _, revoker := canonicalClientAuthDeps(t, clientID, realSecret)

	engine := NewOSSEngine(deps)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader("token=ANY"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuthHeader(clientID, wrongSecret))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 invalid_client (wrong secret must reject)", w.Code)
	}
	if want := `"error":"invalid_client"`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("body = %q; want it to contain %q", w.Body.String(), want)
	}
	if strings.Contains(w.Body.String(), wrongSecret) || strings.Contains(w.Body.String(), realSecret) {
		t.Errorf("revoke 401 response leaked client_secret: %q", w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" || !strings.Contains(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q; want canonical Basic challenge", got)
	}
	if calls := revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired despite invalid client auth: %v", calls)
	}
}

// TestOSSEngine_RevokeRejectsUnknownClientWithInvalidClient pins
// that an unknown client_id is wire-indistinguishable from a wrong
// secret — both return 401 invalid_client. This is RFC 6749 §5.2 +
// the documented OSS opaque-failure contract on
// ErrInvalidOAuthClientCredentials.
func TestOSSEngine_RevokeRejectsUnknownClientWithInvalidClient(t *testing.T) {
	const realClient = "cli-known"
	const realSecret = "S"
	deps, _, _ := canonicalClientAuthDeps(t, realClient, realSecret)

	form := "token=ANY&client_id=cli-unknown&client_secret=ANYTHING"
	w := postRevoke(t, deps, form)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 invalid_client (unknown client)", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_client"`) {
		t.Errorf("body = %q; want invalid_client", w.Body.String())
	}
}

// TestOSSEngine_RevokeDoesNotRequireSiteAdminWhenClientAuthWired
// pins the negative case: when the canonical OAuthClientAuth chain
// is wired into OSSRouterDeps, the route MUST consume it via
// mw.RequireOAuthClient (RFC 7009 §2.1) — not via
// mw.RequireSiteAdmin (the no-runtime-wiring fallback). A request
// carrying a valid OAuth client credential but NO site-admin
// bearer token still succeeds.
func TestOSSEngine_RevokeDoesNotRequireSiteAdminWhenClientAuthWired(t *testing.T) {
	const clientID = "cli-no-site-admin"
	const clientSecret = "S"
	deps, _, _ := canonicalClientAuthDeps(t, clientID, clientSecret)

	engine := NewOSSEngine(deps)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", strings.NewReader("token=ANY"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuthHeader(clientID, clientSecret))
	// Deliberately NO Authorization-Bearer site-admin header.
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (site_admin MUST NOT be required when client auth is wired); body=%q", w.Code, w.Body.String())
	}
}

// TestOSSEngine_RevokeFallsBackToSiteAdminWhenClientAuthNil pins
// the documented scaffold-mode fallback: when OAuthClientAuth is
// nil on OSSRouterDeps (no-DB scaffold, or a deliberate "client-
// auth not yet wired" deployment), the route falls back to
// mw.RequireSiteAdmin and an unauthenticated caller is rejected
// with 401 — the canonical OSS safe default that protects the
// surface without leaking implementation detail.
func TestOSSEngine_RevokeFallsBackToSiteAdminWhenClientAuthNil(t *testing.T) {
	verifier := &fakeIntrospectionVerifier{
		claims: &service.IntrospectionClaims{
			Sub:      uuid.New().String(),
			ClientID: "any",
			Jti:      "JTI-FALLBACK",
			Exp:      4102444800,
		},
	}
	deps := OSSRouterDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:       &service.RecorderSessionRevoker{},
		// OAuthClientAuth: nil → fallback path.
		Audit: &audit.Recorder{},
	}
	w := postRevoke(t, deps, "token=ANY")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (scaffold fallback rejects unauthenticated)", w.Code)
	}
}

// TestOSSEngine_RevokeMissingClientCredentialReturnsInvalidClient
// pins that a request with NO Basic header AND NO client_id/secret
// form fields fails the wired auth path with 401 invalid_client
// rather than reaching the handler body. Protects against a future
// edit that "helpfully" admits empty credentials when client auth
// is wired.
func TestOSSEngine_RevokeMissingClientCredentialReturnsInvalidClient(t *testing.T) {
	deps, _, revoker := canonicalClientAuthDeps(t, "cli-x", "S")
	w := postRevoke(t, deps, "token=ANY")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 invalid_client (no credentials supplied)", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_client"`) {
		t.Errorf("body = %q; want invalid_client", w.Body.String())
	}
	if calls := revoker.Calls(); len(calls) != 0 {
		t.Errorf("session revoker fired despite missing credentials: %v", calls)
	}
}
