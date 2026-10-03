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

func consentDeny(t *testing.T, clientID, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	client := &domain.Client{
		ClientID:     "cli-1",
		Name:         "Test",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scope:        "openid",
	}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"})

	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, authorizePrincipal()); c.Next() })
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(ConsentHandlerDeps{
		AuthorizeService: authzSvc,
		Clients:          clients,
		Audit:            &audit.Recorder{},
	}))
	form := url.Values{}
	form.Set("action", "deny")
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("state", "s1")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Denying consent redirects only to a redirect URI registered for the client;
// any other value is answered with 400 and no Location.
func TestConsentDeny_RedirectsOnlyToRegisteredURI(t *testing.T) {
	if w := consentDeny(t, "cli-1", "https://other.example/cb"); w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Errorf("deny with an unregistered redirect_uri: status=%d location=%q, want 400 and none", w.Code, w.Header().Get("Location"))
	}
	w := consentDeny(t, "cli-1", "https://app.example.com/cb")
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "https://app.example.com/cb?") {
		t.Errorf("deny with the registered redirect_uri: status=%d location=%q, want 302 to it", w.Code, w.Header().Get("Location"))
	}
}
