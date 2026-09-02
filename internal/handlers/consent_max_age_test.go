package handlers

// consent_max_age_test.go — THE-PROFILE-CLAIMS item 0: the consent page
// echoes max_age, so an approve resumes the authorize request WITH its
// freshness requirement. Before the fix the hidden fields dropped it and a
// max_age request that needed fresh consent resumed without any max_age.

import (
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

// newMaxAgeConsentEngine wires consent + authorize with a session that
// authenticated an HOUR ago, so max_age=60 must force re-login while no
// max_age mints straight through.
func newMaxAgeConsentEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	principal := authorizePrincipal()
	oldSession := &domain.Session{
		ID: principal.SessionID, UserID: principal.UserID, IsValid: true,
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour),
	}
	client := &domain.Client{ClientID: "cli-1", Name: "Test", RedirectURIs: []string{"https://app.example.com/cb"}, SkipConsent: false, Scope: "openid profile"}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	consentSvc := service.NewConsentService(nil, &captureConsentRepo{})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithConsentService(consentSvc).
		WithSessionLookup(&fakeSessionLookup{session: oldSession})
	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, principal); c.Next() })
	deps := ConsentHandlerDeps{ConsentService: consentSvc, AuthorizeService: authzSvc, Clients: clients, Audit: &audit.Recorder{}}
	r.GET("/api/v1/oauth/consent", HandleConsentForm(deps))
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(deps))
	return r
}

func TestConsentForm_EchoesMaxAge(t *testing.T) {
	r := newMaxAgeConsentEngine(t)
	q := url.Values{"client_id": {"cli-1"}, "redirect_uri": {"https://app.example.com/cb"}, "scope": {"openid"}, "max_age": {"60"}, "acr_values": {"urn:identuum:loa:mfa"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/consent?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `name="max_age" value="60"`) {
		t.Errorf("consent page must echo max_age as a hidden field:\n%s", w.Body.String())
	}
	// THE-HONEST-ACR: acr_values survives the consent round-trip too, so the
	// resumed authorize still enforces the requested rung.
	if !strings.Contains(w.Body.String(), `name="acr_values" value="urn:identuum:loa:mfa"`) {
		t.Errorf("consent page must echo acr_values as a hidden field:\n%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `name="prompt"`) {
		t.Errorf("prompt must NOT be echoed (prompt=consent would loop the consent page)")
	}
}

// Approve WITH the echoed max_age resumes the freshness requirement: a
// session older than max_age is sent back to login instead of minting a
// code. The same approve without max_age mints.
func TestConsentSubmit_ApproveCarriesMaxAgeThrough(t *testing.T) {
	post := func(t *testing.T, r *gin.Engine, maxAge string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{}
		form.Set("action", "approve")
		form.Set("client_id", "cli-1")
		form.Set("redirect_uri", "https://app.example.com/cb")
		form.Set("scope", "openid")
		form.Set("response_type", "code")
		form.Set("code_challenge", "testchallenge")
		form.Set("code_challenge_method", "S256")
		form.Set("state", "st")
		if maxAge != "" {
			form.Set("max_age", maxAge)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	// Control: no max_age → approve mints a code at the redirect_uri.
	w := post(t, newMaxAgeConsentEngine(t), "")
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example.com/cb") || !strings.Contains(loc, "code=") {
		t.Fatalf("control approve: status=%d location=%q, want a code redirect", w.Code, loc)
	}
	// max_age=60 against an hour-old session → the resumed request enforces
	// freshness: login is required again, no code is minted.
	w = post(t, newMaxAgeConsentEngine(t), "60")
	loc = w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.Contains(loc, "/api/v1/auth/browser-login?return_to=") {
		t.Fatalf("approve with max_age=60 on an hour-old session: status=%d location=%q, want the login redirect (freshness carried through)", w.Code, loc)
	}
	if strings.Contains(loc, "code=") {
		t.Errorf("a code must not be minted when max_age is exceeded: %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("max_age=60")) && !strings.Contains(loc, "max_age%3D60") {
		t.Errorf("the login return_to must keep max_age so the fresh session is re-checked: %q", loc)
	}
	_ = uuid.Nil
}
