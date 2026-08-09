package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// captureConsentRepo is a minimal OAuthConsentRepository that records the
// last Upsert so the test can assert what scope HandleConsentSubmit persisted.
type captureConsentRepo struct{ last *domain.OAuthConsent }

func (r *captureConsentRepo) Upsert(_ context.Context, c *domain.OAuthConsent) (*domain.OAuthConsent, error) {
	cp := *c
	r.last = &cp
	return &cp, nil
}

func (r *captureConsentRepo) GetActive(_ context.Context, _ uuid.UUID, _, _ string) (*domain.OAuthConsent, error) {
	return r.last, nil
}

func (r *captureConsentRepo) Revoke(_ context.Context, _ uuid.UUID, _, _ string, _ time.Time) error {
	return nil
}

// (d) R6 — HandleConsentSubmit persists the CLAMPED scope (intersection with
// the client's registered scopes), not the raw requested superset.
func TestConsentSubmitR6_PersistsClampedScope(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	consentRepo := &captureConsentRepo{}
	consentSvc := service.NewConsentService(nil, consentRepo)

	client := &domain.Client{
		ClientID:     "cli-1",
		Name:         "Test",
		RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent:  false,
		Scope:        "openid profile", // registered set
	}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithConsentService(consentSvc)

	principal := authorizePrincipal()
	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, principal); c.Next() })
	// Mount the handler directly (CookieSession nil → principal resolves from
	// the injected context principal; bypasses the RegisterConsentRoutes
	// non-nil-CookieSession guard).
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(ConsentHandlerDeps{
		ConsentService:   consentSvc,
		AuthorizeService: authzSvc,
		CookieSession:    nil,
		Clients:          clients,
		Audit:            &audit.Recorder{},
	}))

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("client_id", "cli-1")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("scope", "openid profile email") // superset — "email" is NOT registered
	form.Set("response_type", "code")
	form.Set("code_challenge", "testchallenge")
	form.Set("code_challenge_method", "S256")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if consentRepo.last == nil {
		t.Fatalf("consent was not persisted (status=%d body=%s)", w.Code, w.Body.String())
	}
	t.Logf("EVIDENCE (d) consent submit: status=%d persistedScope=%q (raw requested was \"openid profile email\")", w.Code, consentRepo.last.Scope)
	if consentRepo.last.Scope != "openid profile" {
		t.Fatalf("persisted consent scope = %q, want \"openid profile\" (clamped; unregistered \"email\" dropped)", consentRepo.last.Scope)
	}
	// And the flow completed to a redirect (consent covered the clamped scope).
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (approve → authorize mints code)", w.Code)
	}
}
