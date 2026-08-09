package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func newFrontchannelEngine(t *testing.T) (*gin.Engine, *service.CookieSessionService, *service.UserSessionService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	RegisterFrontchannelLogoutRoutes(r, FrontchannelLogoutHandlerDeps{
		CookieSession: cookies,
		UserSession:   sessions,
		Audit:         &audit.Recorder{},
	})
	return r, cookies, sessions
}

func TestFrontchannelLogout_NoCookieReturns200(t *testing.T) {
	r, _, _ := newFrontchannelEngine(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "signed out") {
		t.Errorf("body missing logout message: %q", w.Body.String())
	}
}

func TestFrontchannelLogout_AlwaysClearsCookie(t *testing.T) {
	r, _, _ := newFrontchannelEngine(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil))
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "identuum_session=") {
		t.Errorf("Set-Cookie missing: %q", setCookie)
	}
}

func TestFrontchannelLogout_CSPSetForIframeUse(t *testing.T) {
	r, _, _ := newFrontchannelEngine(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("CSP missing")
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %q", csp)
	}
}

func TestFrontchannelLogout_NoScriptInBody(t *testing.T) {
	r, _, _ := newFrontchannelEngine(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil))
	if strings.Contains(strings.ToLower(w.Body.String()), "<script") {
		t.Errorf("body contains <script>: %q", w.Body.String())
	}
}

// newFrontchannelEngineWithClient wires the iframe variant.
func newFrontchannelEngineWithClient(t *testing.T, client *domain.Client, issuer string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	deps := FrontchannelLogoutHandlerDeps{
		CookieSession: cookies,
		UserSession:   sessions,
		Audit:         &audit.Recorder{},
		Issuer:        issuer,
	}
	if client != nil {
		deps.Clients = &fakeLogoutClientLookup{client: client}
	}
	RegisterFrontchannelLogoutRoutes(r, deps)
	return r
}

func TestFrontchannelLogout_NoClientIDRendersFallback(t *testing.T) {
	r := newFrontchannelEngineWithClient(t, &domain.Client{ClientID: "cli-1", FrontchannelLogoutURI: "https://app.example.com/fc-logout"}, "https://idp.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout", nil))
	if strings.Contains(w.Body.String(), "<iframe") {
		t.Errorf("iframe rendered without client_id query: %q", w.Body.String())
	}
}

func TestFrontchannelLogout_RegisteredClientRendersIframe(t *testing.T) {
	r := newFrontchannelEngineWithClient(t, &domain.Client{
		ClientID:              "cli-1",
		FrontchannelLogoutURI: "https://app.example.com/fc-logout",
	}, "https://idp.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout?client_id=cli-1", nil))
	if !strings.Contains(w.Body.String(), `<iframe src="https://app.example.com/fc-logout"`) {
		t.Errorf("iframe missing: %q", w.Body.String())
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src https://app.example.com") {
		t.Errorf("CSP frame-src missing: %q", csp)
	}
}

func TestFrontchannelLogout_HostileURIBlockedByValidation(t *testing.T) {
	r := newFrontchannelEngineWithClient(t, &domain.Client{
		ClientID:              "cli-1",
		FrontchannelLogoutURI: "http://app.example.com/fc-logout", // HTTP not allowed
	}, "https://idp.test")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout?client_id=cli-1", nil))
	if strings.Contains(w.Body.String(), "<iframe") {
		t.Errorf("iframe rendered with invalid URI: %q", w.Body.String())
	}
}

func TestFrontchannelLogout_SessionRequiredEmitsIssAndSid(t *testing.T) {
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	uid := uuid.New()
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uid, Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uid})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterFrontchannelLogoutRoutes(r, FrontchannelLogoutHandlerDeps{
		CookieSession: cookies,
		UserSession:   sessions,
		Issuer:        "https://idp.test",
		Clients: &fakeLogoutClientLookup{client: &domain.Client{
			ClientID:                          "cli-1",
			FrontchannelLogoutURI:             "https://app.example.com/fc-logout",
			FrontchannelLogoutSessionRequired: true,
		}},
		Audit: &audit.Recorder{},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout?client_id=cli-1", nil)
	req.AddCookie(cookies.Issue(issued.RefreshToken, issued.ExpiresAt))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "iss=https") {
		t.Errorf("iss missing in iframe: %q", body)
	}
	if !strings.Contains(body, "sid=") {
		t.Errorf("sid missing in iframe: %q", body)
	}
}
