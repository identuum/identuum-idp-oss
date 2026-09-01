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
	// response_type is REQUIRED since THE-PKCE-DECISION (no silent
	// default-to-code); the helper supplies it unless a test overrides.
	q.Set("response_type", "code")
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

// A BROWSER (Accept: text/html) hitting a pre-redirect-uri failure gets a
// terminal HTML error page with 200 — never a redirect, never a 4xx the
// scripted conformance browser would throw on. API clients (no text/html
// Accept) keep the 400 JSON envelope, pinned by the sibling tests above.
// RULE: AUTHZ-BROWSER-CEREMONY-1
func TestAuthorize_DirectErrorRendersHTMLForBrowsers(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), authorizePrincipal())
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":    "cli-1",
		"redirect_uri": "https://imposter.example.com/cb",
	}), nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (terminal human-facing error page)", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("direct error must never redirect; got Location %q", loc)
	}
	body := w.Body.String()
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(body, "Authorization error") || !strings.Contains(body, "error") {
		t.Errorf("browser error page wrong: ct=%q body=%q", w.Header().Get("Content-Type"), body)
	}
}

// ---------- Redirect-safe 302 ----------

// THE-PKCE-DECISION (DO-3): an unauthenticated INTERACTIVE request is sent to
// the OP's own browser-login form with the full authorize URL as return_to —
// not error-redirected back to the client. The error redirect survives ONLY
// under prompt=none (OIDC Core §3.1.2.6), pinned separately below.
func TestAuthorize_NoSessionRedirectsToBrowserLogin(t *testing.T) {
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
	if !strings.HasPrefix(loc, "/api/v1/auth/browser-login?return_to=") {
		t.Errorf("location = %q, want browser-login redirect", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("/api/v1/oauth/authorize?")) {
		t.Errorf("return_to does not carry the authorize URL: %q", loc)
	}
}

// OIDC Core §3.1.2.1: the authorize endpoint accepts a form-serialized
// POST with identical semantics. An anonymous POST redirects to
// browser-login with a return_to that re-encodes EVERY submitted form
// parameter as a GET authorize URL — including parameters the handler
// itself does not read (unknown-parameter passthrough).
func TestAuthorize_PostFormRedirectsToBrowserLoginWithFullQuery(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), nil)
	w := httptest.NewRecorder()
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", "cli-1")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("code_challenge", "x")
	form.Set("code_challenge_method", "S256")
	form.Set("state", "abc")
	form.Set("unknown_extension_param", "keep-me")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/v1/auth/browser-login?return_to=") {
		t.Fatalf("location = %q, want browser-login redirect", loc)
	}
	returnTo, err := url.QueryUnescape(strings.TrimPrefix(loc, "/api/v1/auth/browser-login?return_to="))
	if err != nil {
		t.Fatalf("return_to unescape: %v", err)
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		t.Fatalf("return_to parse: %v", err)
	}
	if u.Path != "/api/v1/oauth/authorize" {
		t.Errorf("return_to path = %q", u.Path)
	}
	q := u.Query()
	if q.Get("client_id") != "cli-1" || q.Get("state") != "abc" {
		t.Errorf("return_to lost core params: %q", returnTo)
	}
	if q.Get("unknown_extension_param") != "keep-me" {
		t.Errorf("return_to dropped an unread form parameter: %q", returnTo)
	}
}

func TestAuthorize_NoSessionPromptNoneRedirectsLoginRequired(t *testing.T) {
	r := authorizeEngine(t, preApprovedClient(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id":             "cli-1",
		"redirect_uri":          "https://app.example.com/cb",
		"code_challenge":        "x",
		"code_challenge_method": "S256",
		"state":                 "abc",
		"prompt":                "none",
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

// THE-PKCE-DECISION (DO-3): a signed-in user who has not yet consented is
// sent to the OP's own consent form carrying the full authorize query.
// prompt=none keeps the OIDC-required error redirect, pinned below.
func TestAuthorize_NonPreapprovedRedirectsToConsentForm(t *testing.T) {
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
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/v1/oauth/consent?") {
		t.Errorf("location = %q, want consent-form redirect", loc)
	}
	if !strings.Contains(loc, "client_id=cli-1") || !strings.Contains(loc, "state=abc") {
		t.Errorf("consent redirect does not carry the authorize query: %q", loc)
	}
}

func TestAuthorize_NonPreapprovedPromptNoneRedirectsConsentRequired(t *testing.T) {
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
		"prompt":                "none",
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
