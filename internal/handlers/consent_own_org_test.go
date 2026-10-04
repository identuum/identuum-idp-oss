package handlers

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

// D-027 on the consent page: an app of another organization is an unknown
// client to this user, as /authorize answers. The page does not show its name,
// approving stores no consent for it, and denying redirects nowhere.

func TestConsent_AnAppOfAnotherOrganizationIsAnUnknownClient(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	otherOrg := uuid.New()
	client := &domain.Client{
		ClientID: "cli-1", Name: "Other Tenant App", RedirectURIs: []string{"https://app.example.com/cb"},
		Scope: "openid", OrganizationID: &otherOrg,
	}
	clients := &fakeAuthorizeClientLookup{client: client}
	consentRepo := &captureConsentRepo{}
	consentSvc := service.NewConsentService(nil, consentRepo)
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).WithConsentService(consentSvc)
	deps := ConsentHandlerDeps{ConsentService: consentSvc, AuthorizeService: authzSvc, Clients: clients, Audit: &audit.Recorder{}}

	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, authorizePrincipal()); c.Next() })
	r.GET("/api/v1/oauth/consent", HandleConsentForm(deps))
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(deps))

	q := url.Values{"client_id": {"cli-1"}, "redirect_uri": {"https://app.example.com/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/consent?"+q.Encode(), nil))
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "Other Tenant App") {
		t.Errorf("the consent page for another organization's app = %d; want 400 that does not name it", w.Code)
	}

	for _, action := range []string{"approve", "deny"} {
		form := url.Values{"action": {action}, "client_id": {"cli-1"}, "redirect_uri": {"https://app.example.com/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}, "code_challenge": {"testchallenge"}, "code_challenge_method": {"S256"}}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("%s for another organization's app = %d location=%q; want 400 and no redirect", action, w.Code, w.Header().Get("Location"))
		}
	}
	if consentRepo.last != nil {
		t.Error("a consent row was stored for another organization's app")
	}
}
