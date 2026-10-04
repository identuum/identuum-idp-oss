package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// The phishing-resistant assurance level is earned by a passkey assertion in
// which the authenticator VERIFIED the user (a PIN, a fingerprint, a face).
// A presence-only touch proves possession of one factor. The flag was read off
// the assertion and then ignored at the two places that stamp the rung.

// uvAsserter is fakeAsserter with a controllable user-verification flag.
type uvAsserter struct {
	*fakeAsserter
	uv bool
}

func (a uvAsserter) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*domain.WebAuthnCredential, *domain.User, bool, error) {
	cred, user, _, err := a.fakeAsserter.FinishLogin(ctx, sessionID, r)
	return cred, user, a.uv, err
}

func TestPasskeyStepUp_PresenceOnlyAssertionUpliftsNothing(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	run := func(uv bool) (*httptestResult, *captureUplift) {
		sess := &domain.Session{ID: uuid.New(), UserID: uuid.New(), IsValid: true, Acr: service.ACRPassword}
		user := &domain.User{ID: sess.UserID, Email: "alice@example.com"}
		rec := &captureUplift{}
		r := gin.New()
		RegisterPasskeyStepUpRoutes(r, PasskeyStepUpHandlerDeps{
			CookieSession: &fakeStepUpResolver{resolved: &service.CookieSessionLookupResult{Session: sess, User: user}},
			WebAuthn:      uvAsserter{fakeAsserter: &fakeAsserter{finishUser: user}, uv: uv},
			Sessions:      rec,
			Now:           func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) },
		})
		w := postPasskeyFinish(r, "live", "ceremony-1", "")
		return &httptestResult{code: w.Code, body: w.Body.String()}, rec
	}

	res, rec := run(true)
	if res.code != http.StatusOK || rec.calls != 1 || rec.value != service.ACRPhishingResistant {
		t.Fatalf("a user-verified assertion: %d %s, uplifts=%d (%s); want 200 and one phishing-resistant uplift", res.code, res.body, rec.calls, rec.value)
	}

	res, rec = run(false)
	if res.code != http.StatusUnauthorized || !strings.Contains(res.body, "user_verification_required") {
		t.Errorf("a presence-only assertion: %d %s; want 401 user_verification_required", res.code, res.body)
	}
	if rec.calls != 0 {
		t.Errorf("a presence-only assertion recorded %d uplift(s) to %q; want none", rec.calls, rec.value)
	}
}

type httptestResult struct {
	code int
	body string
}

func TestWebAuthnLoginStampsTheRungTheAssertionEarned(t *testing.T) {
	user := &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Role: domain.RoleOrgUser, Email: "acr@x.test"} // no MFA policy

	acrOf := func(uv bool) string {
		t.Helper()
		repo := newSessionRepoForHandlers()
		deps := WebAuthnHandlerDeps{
			Audit:         r2Deps(user, uv).Audit,
			UserSession:   service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{}),
			LoginFinisher: r2StubLoginFinisher{user: user, uv: uv},
			UserOrgLookup: r2StubUserOrgLookup{user: user},
		}
		code, body := r2RunFinish(deps)
		if code != http.StatusOK {
			t.Fatalf("login (uv=%v) = %d %s; want 200", uv, code, body)
		}
		if len(repo.byID) != 1 {
			t.Fatalf("sessions created = %d, want 1", len(repo.byID))
		}
		for _, s := range repo.byID {
			return s.Acr
		}
		return ""
	}

	if got := acrOf(true); got != service.ACRPhishingResistant {
		t.Errorf("user-verified passkey login stamped %q, want the phishing-resistant rung", got)
	}
	if got := acrOf(false); got != service.ACRPassword {
		t.Errorf("presence-only passkey login stamped %q, want the lowest rung (one factor)", got)
	}
}
