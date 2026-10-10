package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// F1 (OSS-PRE-RELEASE-REVIEW-2026-10-10, OSS-REVIEW-FIXES-1): a front-channel
// logout frame must let the relying party's receiver RUN ITS SCRIPT — a
// receiver that clears its sign-in marker from localStorage or calls its own
// logout API is script-dependent — without letting it control the page that
// frames it. Every frame therefore carries sandbox="allow-scripts", and a
// receiver on another origin than the OP's also gets allow-same-origin (its
// own origin's storage and cookies; the parent stays cross-origin and out of
// reach). A receiver on the OP's own origin never gets both: a same-origin
// document with scripts could lift its own sandbox. The parent page's CSP,
// frame-ancestors, form-action and base-uri stay as they were, and no frame
// ever gets allow-top-navigation, allow-forms, allow-popups or allow-modals.
// Until this slice every frame was sandbox="allow-same-origin" with no
// allow-scripts: the receiver loaded, its script never ran, and the OP
// continued as if the application had been told.

var iframeTagRE = regexp.MustCompile(`<iframe[^>]*>`)

// sandboxOf maps each frame's src to its sandbox attribute.
func sandboxOf(t *testing.T, body string) map[string]string {
	t.Helper()
	out := map[string]string{}
	srcRE := regexp.MustCompile(`\ssrc="([^"]*)"`)
	sandboxRE := regexp.MustCompile(`\ssandbox="([^"]*)"`)
	for _, tag := range iframeTagRE.FindAllString(body, -1) {
		src := srcRE.FindStringSubmatch(tag)
		sandbox := sandboxRE.FindStringSubmatch(tag)
		if src == nil || sandbox == nil {
			t.Fatalf("iframe without src or sandbox: %s", tag)
		}
		out[src[1]] = sandbox[1]
	}
	return out
}

func assertNoParentControl(t *testing.T, body, csp string) {
	t.Helper()
	for _, forbidden := range []string{"allow-top-navigation", "allow-forms", "allow-popups", "allow-modals", "allow-pointer-lock", "allow-downloads"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("a frame carries %s: %q", forbidden, iframeTagRE.FindAllString(body, -1))
		}
	}
	for _, d := range []string{"default-src 'none'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("parent CSP %q lacks %q", csp, d)
		}
	}
	if strings.Contains(csp, "'unsafe-inline'; script") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("parent CSP admits inline script: %q", csp)
	}
}

const (
	sandboxCrossOrigin = "allow-scripts allow-same-origin"
	sandboxSameOrigin  = "allow-scripts"
)

func TestEndSession_FramesLetACrossOriginReceiverRunItsScript(t *testing.T) {
	for _, target := range []string{
		"/api/v1/oidc/logout",
		"/api/v1/oidc/logout?client_id=fc-a&post_logout_redirect_uri=https%3A%2F%2Fa.example%2Fafter&state=xyz",
	} {
		w := newFCWorld(t, true)
		rec := w.logout(target)
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d; want the page carrying the frames", target, rec.Code)
		}
		got := sandboxOf(t, body)
		wantA := "https://a.example/fc?iss=https%3A%2F%2Fidp.test&amp;sid=" + w.sessionID.String()
		if len(got) != 2 || got[wantA] != sandboxCrossOrigin || got["https://b.example/fc?rp=b"] != sandboxCrossOrigin {
			t.Errorf("%s: frame sandboxes = %v; want both receivers (other origins than the OP's) at %q", target, got, sandboxCrossOrigin)
		}
		assertNoParentControl(t, body, rec.Header().Get("Content-Security-Policy"))
	}
}

// fcWorldWith signs a user in with the given relying parties recorded for the
// session and the given issuer (empty: none).
func fcWorldWith(t *testing.T, issuer string, apps clientsByClientID, rps []string) fcWorld {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	r := gin.New()
	RegisterEndSessionRoutes(r, EndSessionHandlerDeps{
		CookieSession: cookies, UserSession: sessions, Clients: apps, Issuer: issuer, Audit: &audit.Recorder{},
		SessionRPs: rpsFake{issued.Session.ID: rps},
	})
	return fcWorld{r: r, cookie: cookies.Issue(issued.RefreshToken, issued.ExpiresAt), sessionID: issued.Session.ID}
}

// A receiver registered on the OP's own origin runs its script in an opaque
// origin: allow-scripts without allow-same-origin. Since OSS-REVIEW-FIXES-3
// (review OSS-PKCE-REVIEW-2026-10-10 R3) the other receiver of that mixed
// fan-out runs scripts-only too (logout_frontchannel_mixed_fanout_test.go).
func TestEndSession_AReceiverOnTheOPsOriginNeverGetsAllowSameOriginWithScripts(t *testing.T) {
	w := fcWorldWith(t, "https://idp.test", clientsByClientID{
		"fc-self":  {ClientID: "fc-self", FrontchannelLogoutURI: "https://idp.test/rp/fc"},
		"fc-other": {ClientID: "fc-other", FrontchannelLogoutURI: "https://other.example/fc"},
	}, []string{"fc-self", "fc-other"})
	rec := w.logout("/api/v1/oidc/logout")
	got := sandboxOf(t, rec.Body.String())
	if len(got) != 2 || got["https://idp.test/rp/fc"] != sandboxSameOrigin || got["https://other.example/fc"] != sandboxSameOrigin {
		t.Errorf("frame sandboxes = %v; want both receivers of the mixed fan-out at %q", got, sandboxSameOrigin)
	}
	assertNoParentControl(t, rec.Body.String(), rec.Header().Get("Content-Security-Policy"))
}

// With no issuer to compare against, no receiver gets allow-same-origin.
func TestEndSession_WithoutAnIssuerNoReceiverGetsAllowSameOrigin(t *testing.T) {
	w := fcWorldWith(t, "", clientsByClientID{"fc-b": {ClientID: "fc-b", FrontchannelLogoutURI: "https://b.example/fc"}}, []string{"fc-b"})
	got := sandboxOf(t, w.logout("/api/v1/oidc/logout").Body.String())
	if len(got) != 1 || got["https://b.example/fc"] != sandboxSameOrigin {
		t.Errorf("frame sandboxes = %v; want %q (the OP's origin is unknown, so same-origin cannot be ruled out)", got, sandboxSameOrigin)
	}
}

// The passive endpoint (GET /api/v1/oidc/frontchannel-logout?client_id=)
// frames one receiver under the same rule.
func TestFrontchannelLogout_TheFrameLetsTheReceiverRunItsScript(t *testing.T) {
	for _, tc := range []struct {
		uri, want string
	}{
		{"https://app.example.com/fc-logout", sandboxCrossOrigin},
		{"https://idp.test/rp/fc-logout", sandboxSameOrigin},
	} {
		r := newFrontchannelEngineWithClient(t, &domain.Client{ClientID: "cli-1", FrontchannelLogoutURI: tc.uri}, "https://idp.test")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/frontchannel-logout?client_id=cli-1", nil))
		got := sandboxOf(t, w.Body.String())
		if len(got) != 1 || got[tc.uri] != tc.want {
			t.Errorf("%s: frame sandboxes = %v; want %q", tc.uri, got, tc.want)
		}
		for _, forbidden := range []string{"allow-top-navigation", "allow-forms", "allow-popups", "allow-modals"} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Errorf("%s: the frame carries %s", tc.uri, forbidden)
			}
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("%s: CSP %q", tc.uri, csp)
		}
	}
}

func TestFrontchannelFrameSandbox(t *testing.T) {
	for _, tc := range []struct {
		src, issuer, want string
	}{
		{"https://a.example/fc", "https://idp.test", sandboxCrossOrigin},
		{"https://idp.test/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test:443/fc", "https://idp.test", sandboxSameOrigin}, // the browser's origin drops the default port
		{"https://IDP.test/fc", "https://idp.test", sandboxSameOrigin},
		{"https://idp.test:8443/fc", "https://idp.test", sandboxCrossOrigin},
		{"http://idp.test/fc", "https://idp.test", sandboxCrossOrigin},
		{"https://a.example/fc", "", sandboxSameOrigin},
		{"https://a.example/fc", "idp.test", sandboxSameOrigin},
	} {
		if got := frontchannelFrameSandbox(tc.src, tc.issuer); got != tc.want {
			t.Errorf("frontchannelFrameSandbox(%q, %q) = %q, want %q", tc.src, tc.issuer, got, tc.want)
		}
	}
}
