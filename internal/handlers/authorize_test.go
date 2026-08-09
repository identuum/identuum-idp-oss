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

// ---------- helpers ----------

type fakeAuthorizeClientLookup struct {
	client *domain.Client
}

func (f *fakeAuthorizeClientLookup) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	return f.client, nil
}

func authorizeEngine(t *testing.T, client *domain.Client, principal *domain.Principal) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	clients := &fakeAuthorizeClientLookup{client: client}
	svc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"})

	if principal != nil {
		r.Use(func(c *gin.Context) {
			mw.SetPrincipal(c, principal)
			c.Next()
		})
	}
	RegisterAuthorizeRoutes(r, AuthorizeHandlerDeps{
		AuthorizeService: svc,
		Audit:            &audit.Recorder{},
	})
	return r
}

func authorizeURL(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return "/api/v1/oauth/authorize?" + q.Encode()
}

func preApprovedClient() *domain.Client {
	return &domain.Client{
		ClientID:     "cli-1",
		Name:         "Test",
		RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent:  true,
	}
}

func authorizePrincipal() *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		SessionID:      uuid.New(),
		Email:          "alice@example.com",
		Role:           domain.RoleOrgUser,
	}
}

// ---------- Route presence ----------

func TestAuthorize_RouteAbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAuthorizeRoutes(r, AuthorizeHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/authorize", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------- Direct 400 (pre-redirect-uri) ----------

func TestAuthorize_MissingClientIDReturns400(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"redirect_uri": "https://app.example.com/cb",
	}), nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestAuthorize_UnknownClientReturns400(t *testing.T) {
	r := authorizeEngine(t, nil, authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":    "cli-1",
		"redirect_uri": "https://app.example.com/cb",
	}), nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_client"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestAuthorize_UnregisteredRedirectURIReturns400(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":    "cli-1",
		"redirect_uri": "https://imposter.example.com/cb",
	}), nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------- Redirect-safe 302 ----------

func TestAuthorize_NoSessionRedirectsLoginRequired(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":             "cli-1",
		"redirect_uri":          "https://app.example.com/cb",
		"code_challenge":        "x",
		"code_challenge_method": "S256",
		"state":                 "abc",
	}), nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=login_required") {
		t.Errorf("location = %q", loc)
	}
	if !strings.Contains(loc, "state=abc") {
		t.Errorf("state echo missing: %q", loc)
	}
}

func TestAuthorize_NonPreapprovedRedirectsConsentRequired(t *testing.T) {
	client := preApprovedClient()
	client.SkipConsent = false
	r := authorizeEngine(t, client, authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":             "cli-1",
		"redirect_uri":          "https://app.example.com/cb",
		"code_challenge":        "x",
		"code_challenge_method": "S256",
		"state":                 "abc",
	}), nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "error=consent_required") {
		t.Errorf("location = %q", w.Header().Get("Location"))
	}
}

func TestAuthorize_PlainChallengeMethodRedirectsInvalidRequest(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":             "cli-1",
		"redirect_uri":          "https://app.example.com/cb",
		"code_challenge":        "x",
		"code_challenge_method": "plain",
		"state":                 "abc",
	}), nil))
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
		t.Errorf("location = %q", w.Header().Get("Location"))
	}
}

// ---------- Success ----------

func TestAuthorize_SuccessRedirectsWithCodeAndState(t *testing.T) {
	_, challenge := authCodePKCEPair(t)
	r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":             "cli-1",
		"redirect_uri":          "https://app.example.com/cb",
		"response_type":         "code",
		"scope":                 "openid profile",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"state":                 "abc",
	}), nil))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Errorf("code missing in redirect")
	}
	if loc.Query().Get("state") != "abc" {
		t.Errorf("state = %q", loc.Query().Get("state"))
	}
	if loc.Query().Get("iss") != "https://idp.test" {
		t.Errorf("iss = %q", loc.Query().Get("iss"))
	}
	// Gin's c.Redirect writes a stdlib `Found` body that echoes
	// the Location URL — that is the standard HTTP 302 wire shape
	// (RFC 7231 §6.4) and NOT a leak; the raw code travels in the
	// Location header on purpose.
}
