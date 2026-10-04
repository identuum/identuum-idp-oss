package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// H2, consent: approving a consent records the grant and mints a code, so a
// bearer-token principal must not reach it either. The same request from a
// browser-session principal is served.
func TestConsent_BearerTokenPrincipalRecordsNothing(t *testing.T) {
	run := func(t *testing.T, tokenID string) (*httptest.ResponseRecorder, *captureConsentRepo, *handlerAuthCodeRepo) {
		t.Helper()
		gin.SetMode(gin.ReleaseMode)
		consentRepo := &captureConsentRepo{}
		consentSvc := service.NewConsentService(nil, consentRepo)
		clients := &fakeAuthorizeClientLookup{client: &domain.Client{
			ClientID: "cli-1", Name: "Test", RedirectURIs: []string{"https://app.example.com/cb"}, Scope: "openid profile email",
		}}
		codeRepo := newAuthCodeRepoForHandlers()
		codes := service.NewAuthorizationCodeService(nil, codeRepo, service.AuthorizationCodeServiceOptions{TTL: time.Hour})
		authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
			WithConsentService(consentSvc)
		p := authorizePrincipal()
		p.TokenID = tokenID
		r := gin.New()
		r.Use(func(c *gin.Context) { mw.SetPrincipal(c, p); c.Next() })
		deps := ConsentHandlerDeps{ConsentService: consentSvc, AuthorizeService: authzSvc, Clients: clients, Audit: &audit.Recorder{}}
		r.POST("/api/v1/oauth/consent", HandleConsentSubmit(deps))

		form := url.Values{}
		form.Set("action", "approve")
		form.Set("client_id", "cli-1")
		form.Set("redirect_uri", "https://app.example.com/cb")
		form.Set("scope", "openid")
		form.Set("response_type", "code")
		form.Set("code_challenge", "testchallenge")
		form.Set("code_challenge_method", "S256")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w, consentRepo, codeRepo
	}

	w, consentRepo, codeRepo := run(t, "")
	if consentRepo.last == nil || len(codeRepo.byID) != 1 {
		t.Fatalf("browser-session principal: %d, grant=%v, codes=%d; want the grant recorded and one code", w.Code, consentRepo.last, len(codeRepo.byID))
	}

	w, consentRepo, codeRepo = run(t, "jti-of-a-bearer-token")
	if consentRepo.last != nil || len(codeRepo.byID) != 0 {
		t.Errorf("bearer principal: %d, grant=%v, codes=%d; want nothing recorded and no code", w.Code, consentRepo.last, len(codeRepo.byID))
	}
}

// H2: authorize acts for a browser session. A principal that came from a
// bearer token (it carries the token's jti) is not one — a holder of someone's
// access token must not be able to mint codes for apps as that user.
func TestAuthorize_BearerTokenPrincipalDoesNotMintACode(t *testing.T) {
	params := map[string]string{
		"client_id":    "cli-1",
		"redirect_uri": "https://app.example.com/cb",
		"scope":        "openid",
	}

	t.Run("a browser-session principal is served", func(t *testing.T) {
		r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(params), nil))
		if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://app.example.com/cb?") ||
			!strings.Contains(w.Header().Get("Location"), "code=") {
			t.Fatalf("session principal: %d %q; want a redirect to the app with a code", w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("a bearer-token principal is not", func(t *testing.T) {
		p := authorizePrincipal()
		p.TokenID = "jti-of-a-bearer-token"
		r := authorizeEngine(t, preApprovedClient(), p)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(params), nil))
		if loc := w.Header().Get("Location"); strings.Contains(loc, "code=") || strings.HasPrefix(loc, "https://app.example.com/cb") {
			t.Fatalf("bearer principal minted a code: %d %q", w.Code, loc)
		}
	})
}
