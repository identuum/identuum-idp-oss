package handlers

// Phase 2 of end_session used to revoke the hint's session a second time after
// phase 1 had already ended the cookie session it names, and read the store's
// "session not found" as a store failure: every RP-initiated logout with a
// valid id_token_hint logged AUTH-503 at ERROR and audited
// revocation_unconfirmed=true although the logout had succeeded
// (CONFORMANCE-FULL-1 Q3; owner 2026-10-10). A hint for this browser's session
// is not revoked twice; a session the store no longer finds is already ended;
// a hint naming another live session still ends it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// The in-memory fixture's Revoke answers as the pgx repository's does since
// OSS-HARDENING-2 (UPDATE ... WHERE revoked_at IS NULL; no row changed is
// domain.ErrSessionNotFound), so these tests run over the shared fixture; the
// pgx-faithful wrapper they first needed is gone.
func newHintNoiseWorld(t *testing.T) hintWorld {
	t.Helper()
	return newHintWorldOver(t, newHandlersSessionRepo(), nil, nil)
}

// assertLogoutConfirmed: no AUTH-503 sink call, no revocation_unconfirmed audit
// event, no X-Identuum-Logout marker.
func assertLogoutConfirmed(t *testing.T, label string, w hintWorld, calls []sinkCall, rec *httptest.ResponseRecorder) {
	t.Helper()
	if len(calls) != 0 {
		t.Errorf("%s: AUTH-503 log sink calls = %+v; want none, the logout succeeded", label, calls)
	}
	for _, e := range w.audit.Events() {
		if e.Action == AuditActionLogoutRevocationUnconfirmed {
			t.Errorf("%s: audit event %s recorded (%+v); want none", label, e.Action, e.Metadata)
		}
	}
	if got := rec.Header().Get(LogoutUnconfirmedHeader); got != "" {
		t.Errorf("%s: %s = %q; want the header absent", label, LogoutUnconfirmedHeader, got)
	}
}

func TestEndSession_AHintForThisBrowsersSessionIsNotRevokedTwice(t *testing.T) {
	calls := recordAuthStoreSink(t)
	w := newHintNoiseWorld(t)
	cookie, sid := w.signIn(t, w.user.ID)
	hint := w.sign(t, jwt.MapClaims{"sub": w.user.ID.String(), "sid": sid.String()})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout?id_token_hint="+url.QueryEscape(hint)+
		"&post_logout_redirect_uri="+url.QueryEscape("https://app.example/after")+"&state=xyz", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://app.example/after") || !strings.Contains(rec.Header().Get("Location"), "state=xyz") {
		t.Fatalf("hinted RP-initiated logout = %d %q; want the 302 back to the app with state", rec.Code, rec.Header().Get("Location"))
	}
	if w.alive(cookie) {
		t.Error("the browser's session is still alive")
	}
	assertLogoutConfirmed(t, "hint for the cookie session", w, *calls, rec)
	redirected := false
	for _, e := range w.audit.Events() {
		if e.Action == "user_session.logout.redirected" {
			redirected = true
			if e.Metadata["revocation_unconfirmed"] != false {
				t.Errorf("redirected audit carries revocation_unconfirmed=%v; want false", e.Metadata["revocation_unconfirmed"])
			}
		}
	}
	if !redirected {
		t.Error("user_session.logout.redirected not audited")
	}
}

func TestEndSession_AHintForASessionAlreadyEndedIsNotAStoreError(t *testing.T) {
	calls := recordAuthStoreSink(t)
	w := newHintNoiseWorld(t)
	other := uuid.New()
	_, sid := w.signIn(t, other)
	if err := w.sessions.RevokeSession(context.Background(), sid, "user_requested"); err != nil {
		t.Fatalf("end the session first: %v", err)
	}
	// A browser that has been closed: the hint alone, naming an ended session.
	rec := w.logout(w.sign(t, jwt.MapClaims{"sub": other.String(), "sid": sid.String()}), nil)
	if !signedOut(rec) {
		t.Fatalf("logout with a hint for an ended session = %d; want the signed-out page", rec.Code)
	}
	assertLogoutConfirmed(t, "hint for an ended session", w, *calls, rec)
}

func TestEndSession_AHintNamingAnotherLiveSessionStillEndsIt(t *testing.T) {
	calls := recordAuthStoreSink(t)
	w := newHintNoiseWorld(t)
	cookie, _ := w.signIn(t, w.user.ID)
	otherCookie, otherSid := w.signIn(t, w.user.ID)
	hint := w.sign(t, jwt.MapClaims{"sub": w.user.ID.String(), "sid": otherSid.String()})

	// The hint names another session of this person, so it does not vouch for
	// this browser: the request carries the confirmation the page's link adds.
	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL("/api/v1/oidc/logout?id_token_hint="+url.QueryEscape(hint), cookie), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	if !signedOut(rec) {
		t.Fatalf("confirmed logout with a hint for another session = %d; want the signed-out page", rec.Code)
	}
	if w.alive(cookie) {
		t.Error("the browser's own session is still alive")
	}
	if w.alive(otherCookie) {
		t.Error("the session the hint names is still alive; a hint for another live session must still end it")
	}
	assertLogoutConfirmed(t, "hint for another live session", w, *calls, rec)
}
