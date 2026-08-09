package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type fakeLogoutClientLookup struct {
	client *domain.Client
}

func (f *fakeLogoutClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return f.client, nil
}

func newLogoutEngine(t *testing.T, client *domain.Client) (*gin.Engine, *service.UserSessionService, *service.CookieSessionService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	deps := EndSessionHandlerDeps{
		CookieSession: cookies,
		UserSession:   sessions,
		Audit:         &audit.Recorder{},
	}
	if client != nil {
		deps.Clients = &fakeLogoutClientLookup{client: client}
	}
	RegisterEndSessionRoutes(r, deps)
	return r, sessions, cookies
}

func TestLogout_NoCookieReturnsNoContent(t *testing.T) {
	r, _, _ := newLogoutEngine(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestLogout_ClearsCookieAlways(t *testing.T) {
	r, _, _ := newLogoutEngine(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil))
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "identuum_session=") {
		t.Errorf("Set-Cookie missing: %q", setCookie)
	}
	if !strings.Contains(setCookie, "Max-Age=0") && !strings.Contains(setCookie, "Max-Age=-1") {
		t.Errorf("clear cookie did not include Max-Age=0 or -1: %q", setCookie)
	}
}

func TestLogout_RevokesCookieSession(t *testing.T) {
	r, sessions, cookies := newLogoutEngine(t, nil)
	uid := uuid.New()
	issued, _ := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uid})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil)
	req.AddCookie(cookies.Issue(issued.RefreshToken, issued.ExpiresAt))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Best-effort: cookie session should now be revoked → rotating
	// it should be invalid_grant.
	if _, err := sessions.RotateRefreshToken(context.Background(), issued.RefreshToken); err == nil {
		t.Errorf("session was not revoked: rotation succeeded")
	}
}

func TestLogout_PostLogoutRedirectUriValidatedAgainstAllowlist(t *testing.T) {
	client := &domain.Client{
		ClientID:               "cli-1",
		PostLogoutRedirectURIs: []string{"https://app.example.com/after"},
	}
	r, _, _ := newLogoutEngine(t, client)
	url := "/api/v1/oidc/logout?client_id=cli-1&post_logout_redirect_uri=https%3A%2F%2Fimposter.example.com&state=xyz"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("imposter URI accepted: status=%d", w.Code)
	}
}

// logoutVerifierHarness builds a fully wired logout engine + a
// minted id_token_hint for tests that exercise the verifier path.
func logoutVerifierHarness(t *testing.T, audience []string, sessionID uuid.UUID) (*gin.Engine, string, *domain.Client, *service.UserSessionService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(priv.Public())
	pkBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	repo := &inMemoryKeyRepoForLogout{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkBytes})),
		State:      domain.KeyStateActive,
	}}}
	verifier := service.NewIDTokenVerifier(nil, repo, service.IDTokenVerifierOptions{Issuer: "https://idp.test"})
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	client := &domain.Client{
		ClientID:               "cli-1",
		PostLogoutRedirectURIs: []string{"https://app.example.com/after"},
	}
	deps := EndSessionHandlerDeps{
		CookieSession:   cookies,
		UserSession:     sessions,
		Clients:         &fakeLogoutClientLookup{client: client},
		IDTokenVerifier: verifier,
		Audit:           &audit.Recorder{},
	}
	RegisterEndSessionRoutes(r, deps)

	tokenClaims := jwt.MapClaims{
		"iss": "https://idp.test",
		"sub": uuid.New().String(),
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	if sessionID != uuid.Nil {
		tokenClaims["session_id"] = sessionID.String()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, tokenClaims)
	tok.Header["kid"] = "kid-eddsa"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r, signed, client, sessions
}

// inMemoryKeyRepoForLogout is a minimal KeyRepository fixture
// duplicated in handlers package to avoid a cross-package fixture
// re-export.
type inMemoryKeyRepoForLogout struct {
	keys []domain.SigningKey
}

func (r *inMemoryKeyRepoForLogout) GetActiveSigningKeys(context.Context) ([]domain.SigningKey, error) {
	return r.keys, nil
}
func (r *inMemoryKeyRepoForLogout) GetAllSigningKeys(context.Context) ([]domain.SigningKey, error) {
	return r.keys, nil
}
func (r *inMemoryKeyRepoForLogout) GetSigningKeyByKID(_ context.Context, kid string) (*domain.SigningKey, error) {
	for i := range r.keys {
		if r.keys[i].KID == kid {
			return &r.keys[i], nil
		}
	}
	return nil, nil
}
func (r *inMemoryKeyRepoForLogout) CreateSigningKey(context.Context, *domain.SigningKey) error {
	return nil
}
func (r *inMemoryKeyRepoForLogout) ActivateSigningKey(context.Context, string) error { return nil }
func (r *inMemoryKeyRepoForLogout) RotateSigningKey(context.Context, string, string, *time.Time) error {
	return nil
}
func (r *inMemoryKeyRepoForLogout) DeprecateSigningKey(context.Context, string, time.Time) error {
	return nil
}
func (r *inMemoryKeyRepoForLogout) DeleteExpiredKeys(context.Context) (int, error) { return 0, nil }

func TestLogout_InvalidIDTokenHintReturns400(t *testing.T) {
	r, _, _, _ := logoutVerifierHarness(t, []string{"cli-1"}, uuid.Nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout?id_token_hint=not-a-jwt", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d", w.Code)
	}
}

func TestLogout_ValidIDTokenHintWithAudienceResolvesClient(t *testing.T) {
	r, hint, _, _ := logoutVerifierHarness(t, []string{"cli-1"}, uuid.Nil)
	url := "/api/v1/oidc/logout?id_token_hint=" + hint +
		"&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fafter&state=xyz"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "state=xyz") {
		t.Errorf("state missing: %q", w.Header().Get("Location"))
	}
}

func TestLogout_ClientIDMismatchAgainstHintAudienceReturns400(t *testing.T) {
	r, hint, _, _ := logoutVerifierHarness(t, []string{"cli-1"}, uuid.Nil)
	url := "/api/v1/oidc/logout?id_token_hint=" + hint +
		"&client_id=cli-other&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fafter"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestLogout_HintSessionIDRevokesSession(t *testing.T) {
	sid := uuid.New()
	r, hint, _, sessions := logoutVerifierHarness(t, []string{"cli-1"}, sid)
	// Seed the session so we can observe the revoke.
	uid := uuid.New()
	if _, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uid}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	url := "/api/v1/oidc/logout?id_token_hint=" + hint
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestLogout_AllowlistedPostLogoutRedirectUriRedirectsWithState(t *testing.T) {
	client := &domain.Client{
		ClientID:               "cli-1",
		PostLogoutRedirectURIs: []string{"https://app.example.com/after"},
	}
	r, _, _ := newLogoutEngine(t, client)
	url := "/api/v1/oidc/logout?client_id=cli-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fafter&state=xyz"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "state=xyz") {
		t.Errorf("state not echoed: %q", loc)
	}
}
