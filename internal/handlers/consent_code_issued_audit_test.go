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

// OSS-POLISH item 5 (audit F7): a code minted through the consent page was not
// audited — HandleConsentSubmit recorded oauth_consent.granted and called
// Authorize, but oauth_authorize.code_issued was recorded only by the
// /authorize handler. Approving consent now records both, in that order.
func TestConsentSubmit_RecordsCodeIssued(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	consentSvc := service.NewConsentService(nil, &captureConsentRepo{})
	client := &domain.Client{ClientID: "cli-1", Name: "Test",
		RedirectURIs: []string{"https://app.example.com/cb"}, Scope: "openid profile"}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithConsentService(consentSvc)
	rec := &audit.Recorder{}

	principal := authorizePrincipal()
	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, principal); c.Next() })
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(ConsentHandlerDeps{
		ConsentService: consentSvc, AuthorizeService: authzSvc, Clients: clients, Audit: rec,
	}))

	form := url.Values{"action": {"approve"}, "client_id": {"cli-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"scope": {"openid profile"}, "response_type": {"code"},
		"code_challenge": {"testchallenge"}, "code_challenge_method": {"S256"}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (a code minted); body=%s", w.Code, w.Body.String())
	}

	var actions []string
	for _, ev := range rec.Events() {
		actions = append(actions, ev.Action)
	}
	if len(actions) != 2 || actions[0] != "oauth_consent.granted" || actions[1] != "oauth_authorize.code_issued" {
		t.Fatalf("audit actions = %v, want [oauth_consent.granted oauth_authorize.code_issued]", actions)
	}
	if got := rec.Events()[1].Metadata["client_id"]; got != "cli-1" {
		t.Fatalf("code_issued client_id = %v, want cli-1", got)
	}
}
