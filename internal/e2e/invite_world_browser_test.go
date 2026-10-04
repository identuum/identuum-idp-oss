//go:build integration

package e2e

import (
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// browserSessionCookieName is the cookie the IdP's own pages sign a person in
// with.
const browserSessionCookieName = "identuum_session"

// browserSession gives the named seeded user a browser session the way the
// login does — a user session plus an opaque browser token — and returns the
// cookie value. /authorize and the consent page act only for such a session
// (H2): a bearer access token does not drive them.
func (w *inviteWorld) browserSession(name string) string {
	w.t.Helper()
	u, err := w.repos.User.GetByID(w.ctx, w.ids[name])
	if err != nil || u == nil {
		w.t.Fatalf("load %s: %v", name, err)
	}
	sessions := service.NewUserSessionService(nil, w.repos.Session, service.UserSessionServiceOptions{})
	issued, err := sessions.CreateUserSession(w.ctx, service.CreateUserSessionInput{UserID: u.ID})
	if err != nil {
		w.t.Fatalf("session %s: %v", name, err)
	}
	tokens := service.NewBrowserSessionTokenService(nil, w.repos.BrowserSessionToken, service.BrowserSessionTokenServiceOptions{})
	org := u.OrganizationID
	tok, err := tokens.Issue(w.ctx, service.IssueBrowserSessionTokenInput{SessionID: issued.Session.ID, UserID: u.ID, OrganizationID: &org})
	if err != nil {
		w.t.Fatalf("browser token %s: %v", name, err)
	}
	return tok.Token
}
