package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Ending a session notifies every relying party that holds an ID token for it
// and registered a back-channel logout endpoint (OIDC Back-Channel Logout 1.0
// §2), not only the one that asked for the logout.

type rpsFake map[uuid.UUID][]string

func (r rpsFake) ClientIDs(_ context.Context, id uuid.UUID) ([]string, error) { return r[id], nil }

type clientsByClientID map[string]*domain.Client

func (m clientsByClientID) GetClientByClientID(_ context.Context, id string) (*domain.Client, error) {
	return m[id], nil
}

type recordingDeliverer struct {
	mu      sync.Mutex
	calls   []service.DeliverInput
	failFor map[string]bool
}

func (r *recordingDeliverer) Deliver(_ context.Context, in service.DeliverInput) (*service.DeliverResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	if r.failFor[in.Client.ClientID] {
		return &service.DeliverResult{Status: http.StatusBadGateway}, errors.New("rp unreachable")
	}
	return &service.DeliverResult{Delivered: true, Status: http.StatusOK}, nil
}

func (r *recordingDeliverer) clientIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.calls))
	for _, c := range r.calls {
		out = append(out, c.Client.ClientID)
	}
	sort.Strings(out)
	return out
}

type fanoutWorld struct {
	r         *gin.Engine
	deliverer *recordingDeliverer
	userID    uuid.UUID
	sessionID uuid.UUID
}

// newFanoutWorld signs a user in and returns the session cookie. With withRPs
// the session has three relying parties recorded: app-a and app-b registered a
// back-channel endpoint, app-c did not.
func newFanoutWorld(t *testing.T, withRPs bool, failFor map[string]bool) (fanoutWorld, *http.Cookie) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	repo := newHandlersSessionRepo()
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	cookie := cookies.Issue(issued.RefreshToken, issued.ExpiresAt)

	apps := clientsByClientID{
		"app-a": {ClientID: "app-a", BackchannelLogoutURI: "https://a.example/bc", PostLogoutRedirectURIs: []string{"https://a.example/after"}},
		"app-b": {ClientID: "app-b", BackchannelLogoutURI: "https://b.example/bc"},
		"app-c": {ClientID: "app-c"},
	}
	deliverer := &recordingDeliverer{failFor: failFor}
	deps := EndSessionHandlerDeps{
		CookieSession: cookies, UserSession: sessions, Clients: apps,
		BackchannelDelivery: deliverer, Audit: &audit.Recorder{},
	}
	if withRPs {
		deps.SessionRPs = rpsFake{issued.Session.ID: {"app-a", "app-b", "app-c"}}
	}
	r := gin.New()
	RegisterEndSessionRoutes(r, deps)
	return fanoutWorld{r: r, deliverer: deliverer, userID: user.ID, sessionID: issued.Session.ID}, cookie
}

func (w fanoutWorld) logout(t *testing.T, cookie *http.Cookie, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL(target, cookie), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	return rec
}

func TestEndSession_NotifiesEveryRelyingPartyOfTheEndedSession(t *testing.T) {
	w, cookie := newFanoutWorld(t, true, nil)
	rec := w.logout(t, cookie, "/api/v1/oidc/logout")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "You are signed out") {
		t.Fatalf("logout = %d; want the signed-out page", rec.Code)
	}
	got := w.deliverer.clientIDs()
	if len(got) != 2 || got[0] != "app-a" || got[1] != "app-b" {
		t.Errorf("notified %v; want app-a and app-b (app-c registered no back-channel endpoint)", got)
	}
	for _, c := range w.deliverer.calls {
		if c.SessionID != w.sessionID || c.Subject != w.userID {
			t.Errorf("logout token for %s carries session %s subject %s; want session %s subject %s", c.Client.ClientID, c.SessionID, c.Subject, w.sessionID, w.userID)
		}
	}
}

func TestEndSession_TheRequestingRelyingPartyIsNotifiedOnce(t *testing.T) {
	w, cookie := newFanoutWorld(t, true, nil)
	rec := w.logout(t, cookie, "/api/v1/oidc/logout?client_id=app-a&post_logout_redirect_uri=https%3A%2F%2Fa.example%2Fafter")
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d; want the 302 back to the app", rec.Code)
	}
	got := w.deliverer.clientIDs()
	if len(got) != 2 || got[0] != "app-a" || got[1] != "app-b" {
		t.Errorf("notified %v; want app-a once and app-b once", got)
	}
}

func TestEndSession_AFailedDeliveryDoesNotStopTheOthersOrTheLogout(t *testing.T) {
	w, cookie := newFanoutWorld(t, true, map[string]bool{"app-a": true})
	rec := w.logout(t, cookie, "/api/v1/oidc/logout")
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d; want it to complete", rec.Code)
	}
	if got := w.deliverer.clientIDs(); len(got) != 2 {
		t.Errorf("notified %v; want both app-a (failed) and app-b to be tried", got)
	}
}

func TestEndSession_WithoutRecordedRelyingPartiesBehavesAsBefore(t *testing.T) {
	w, cookie := newFanoutWorld(t, false, nil)
	_ = w.logout(t, cookie, "/api/v1/oidc/logout")
	if got := w.deliverer.clientIDs(); len(got) != 0 {
		t.Errorf("notified %v with no relying parties recorded and no client named; want none", got)
	}
	w2, cookie2 := newFanoutWorld(t, false, nil)
	_ = w2.logout(t, cookie2, "/api/v1/oidc/logout?client_id=app-a&post_logout_redirect_uri=https%3A%2F%2Fa.example%2Fafter")
	if got := w2.deliverer.clientIDs(); len(got) != 1 || got[0] != "app-a" {
		t.Errorf("notified %v; want only the named client app-a, as before", got)
	}
}
