package handlers

// Ending a session at end_session loads the frontchannel_logout_uri of every
// relying party recorded for that session in a hidden iframe (OIDC
// Front-Channel Logout 1.0 §3) — the same relying-party set the back-channel
// fan-out uses — with iss and sid when that client registered
// frontchannel_logout_session_required, and then continues to the validated
// post_logout_redirect_uri. Before CONFORMANCE-FULL-1 Q2 (owner 2026-10-10)
// discovery advertised frontchannel_logout_supported while end_session never
// loaded a single frame; only GET /api/v1/oidc/frontchannel-logout?client_id=
// did.

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

type fcWorld struct {
	r         *gin.Engine
	deliverer *recordingDeliverer
	audit     *audit.Recorder
	cookie    *http.Cookie
	sessionID uuid.UUID
}

// newFCWorld signs a user in whose session has three relying parties recorded:
// fc-a registered a front-channel URI that requires the session (iss + sid),
// fc-b a front-channel URI without that requirement and a back-channel URI,
// and plain-c neither. fc-d registered a front-channel URI but is not a
// relying party of this session. With withRPs false nothing is recorded.
func newFCWorld(t *testing.T, withRPs bool) fcWorld {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	apps := clientsByClientID{
		"fc-a":    {ClientID: "fc-a", FrontchannelLogoutURI: "https://a.example/fc", FrontchannelLogoutSessionRequired: true, PostLogoutRedirectURIs: []string{"https://a.example/after"}},
		"fc-b":    {ClientID: "fc-b", FrontchannelLogoutURI: "https://b.example/fc?rp=b", BackchannelLogoutURI: "https://b.example/bc"},
		"plain-c": {ClientID: "plain-c", PostLogoutRedirectURIs: []string{"https://c.example/after"}},
		"fc-d":    {ClientID: "fc-d", FrontchannelLogoutURI: "https://d.example/fc", FrontchannelLogoutSessionRequired: true, PostLogoutRedirectURIs: []string{"https://d.example/after"}},
	}
	deliverer := &recordingDeliverer{}
	recorder := &audit.Recorder{}
	deps := EndSessionHandlerDeps{
		CookieSession: cookies, UserSession: sessions, Clients: apps,
		BackchannelDelivery: deliverer, Issuer: "https://idp.test", Audit: recorder,
	}
	if withRPs {
		deps.SessionRPs = rpsFake{issued.Session.ID: {"fc-a", "fc-b", "plain-c"}}
	}
	r := gin.New()
	RegisterEndSessionRoutes(r, deps)
	return fcWorld{r: r, deliverer: deliverer, audit: recorder, cookie: cookies.Issue(issued.RefreshToken, issued.ExpiresAt), sessionID: issued.Session.ID}
}

func (w fcWorld) logout(target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL(target, w.cookie), nil)
	req.AddCookie(w.cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	return rec
}

var iframeSrcRE = regexp.MustCompile(`<iframe[^>]*\ssrc="([^"]*)"`)

func iframeSrcs(body string) []string {
	var out []string
	for _, m := range iframeSrcRE.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestEndSession_LoadsTheFrontchannelLogoutURIOfEachRelyingPartyOfTheEndedSession(t *testing.T) {
	w := newFCWorld(t, true)
	rec := w.logout("/api/v1/oidc/logout")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "You are signed out") {
		t.Fatalf("logout = %d %q; want the signed-out page carrying the frames", rec.Code, rec.Header().Get("Content-Type"))
	}
	srcs := iframeSrcs(body)
	wantA := "https://a.example/fc?iss=https%3A%2F%2Fidp.test&amp;sid=" + w.sessionID.String()
	wantB := "https://b.example/fc?rp=b"
	if len(srcs) != 2 || srcs[0] != wantA || srcs[1] != wantB {
		t.Errorf("iframe srcs = %q; want exactly [%q %q]: iss+sid only where the client required the session, no frame for plain-c (no URI) or fc-d (not a relying party)", srcs, wantA, wantB)
	}
	if strings.Contains(body, "d.example") || strings.Contains(body, "plain-c") || strings.Contains(body, w.cookie.Value) {
		t.Errorf("the page names a client that is not a relying party, or carries the cookie value")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-src https://a.example https://b.example") || strings.Contains(csp, "d.example") {
		t.Errorf("CSP %q: frame-src must list exactly the frames' origins", csp)
	}
	for _, d := range []string{"default-src 'none'", "script-src 'none'", "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %q", csp, d)
		}
	}
	if strings.Contains(strings.ToLower(body), "<script") || strings.Contains(body, "http-equiv=\"refresh\"") {
		t.Errorf("with no redirect the page needs no script and no refresh: %q", body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", cc)
	}
	// The back-channel fan-out still reaches fc-b beside the frame.
	if got := w.deliverer.clientIDs(); len(got) != 1 || got[0] != "fc-b" {
		t.Errorf("back-channel deliveries = %v; want fc-b only", got)
	}
}

func TestEndSession_ContinuesToThePostLogoutRedirectAfterTheFrames(t *testing.T) {
	w := newFCWorld(t, true)
	rec := w.logout("/api/v1/oidc/logout?client_id=fc-a&post_logout_redirect_uri=https%3A%2F%2Fa.example%2Fafter&state=xyz")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("logout = %d; want the 200 page that loads the frames and then continues", rec.Code)
	}
	if len(iframeSrcs(body)) != 2 {
		t.Errorf("iframe srcs = %q; want the two relying parties' frames", iframeSrcs(body))
	}
	const location = "https://a.example/after?state=xyz"
	// Without script the browser continues by the refresh; with script as
	// soon as every frame has loaded, and never later than the script's own
	// timeout; a person can also follow the link.
	if !strings.Contains(body, `<meta http-equiv="refresh" content="`) || !strings.Contains(body, `;url=`+location+`"`) {
		t.Errorf("the page carries no refresh to %s: %q", location, body)
	}
	if !strings.Contains(body, `id="continue" href="`+location+`"`) {
		t.Errorf("the page carries no continue link to %s", location)
	}
	nonce := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9+/=_-]+)'`).FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
	if nonce == nil {
		t.Fatalf("CSP %q grants no nonce for the page's script", rec.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(body, `<script nonce="`+nonce[1]+`">`) || !strings.Contains(body, "setTimeout") {
		t.Errorf("the page's script must carry the CSP nonce and bound its wait with a timeout: %q", body)
	}
	if strings.Contains(body, "unsafe-inline'; script") || strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'unsafe-inline'") {
		t.Errorf("the script is admitted by nonce only")
	}
	redirected := false
	for _, e := range w.audit.Events() {
		if e.Action == "user_session.logout.redirected" {
			redirected = true
			if e.Metadata["client_id"] != "fc-a" || e.Metadata["revocation_unconfirmed"] != false {
				t.Errorf("redirected audit = %+v", e.Metadata)
			}
		}
	}
	if !redirected {
		t.Error("user_session.logout.redirected not audited although the page continues there")
	}
}

// A requesting relying party that was not recorded for the session (no ID
// token minted through this session) still gets its frame, as it still gets
// its logout token on the back-channel.
func TestEndSession_TheRequestingRelyingPartyGetsItsFrameEvenWhenNotRecorded(t *testing.T) {
	w := newFCWorld(t, true)
	rec := w.logout("/api/v1/oidc/logout?client_id=fc-d&post_logout_redirect_uri=https%3A%2F%2Fd.example%2Fafter")
	srcs := iframeSrcs(rec.Body.String())
	want := "https://d.example/fc?iss=https%3A%2F%2Fidp.test&amp;sid=" + w.sessionID.String()
	if rec.Code != http.StatusOK || len(srcs) != 3 || srcs[2] != want {
		t.Errorf("logout = %d, iframe srcs = %q; want the session's two frames and %q", rec.Code, srcs, want)
	}
}

func TestEndSession_WithNoFrontchannelRelyingPartyTheResponsesAreUnchanged(t *testing.T) {
	w := newFCWorld(t, false)
	rec := w.logout("/api/v1/oidc/logout")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "You are signed out") || len(iframeSrcs(rec.Body.String())) != 0 {
		t.Errorf("logout with no relying party = %d; want the plain signed-out page with no frame", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "frame-src") || !strings.Contains(csp, "script-src 'none'") {
		t.Errorf("CSP %q: no frame-src and no script without frames", csp)
	}
	w = newFCWorld(t, false)
	rec = w.logout("/api/v1/oidc/logout?client_id=plain-c&post_logout_redirect_uri=https%3A%2F%2Fc.example%2Fafter&state=s1")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://c.example/after?state=s1" {
		t.Errorf("logout for a client without a front-channel URI = %d %q; want the direct 302", rec.Code, rec.Header().Get("Location"))
	}
}

// A client that requires the session gets no frame when the OP has no issuer
// to name: a half-populated URL would be meaningless to it.
func TestEndSession_NoIssuerSkipsTheFramesThatRequireTheSession(t *testing.T) {
	w := newFCWorld(t, true)
	gin.SetMode(gin.ReleaseMode)
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	issued, _ := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID})
	r := gin.New()
	RegisterEndSessionRoutes(r, EndSessionHandlerDeps{
		CookieSession: cookies, UserSession: sessions, Audit: &audit.Recorder{},
		Clients: clientsByClientID{
			"fc-a": {ClientID: "fc-a", FrontchannelLogoutURI: "https://a.example/fc", FrontchannelLogoutSessionRequired: true},
			"fc-b": {ClientID: "fc-b", FrontchannelLogoutURI: "https://b.example/fc"},
		},
		SessionRPs: rpsFake{issued.Session.ID: {"fc-a", "fc-b"}},
	})
	w.r, w.cookie = r, cookies.Issue(issued.RefreshToken, issued.ExpiresAt)
	srcs := iframeSrcs(w.logout("/api/v1/oidc/logout").Body.String())
	if len(srcs) != 1 || srcs[0] != "https://b.example/fc" {
		t.Errorf("iframe srcs = %q; want only fc-b's frame", srcs)
	}
}
