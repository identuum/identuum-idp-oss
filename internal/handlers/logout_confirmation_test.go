package handlers

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A GET to the end-session endpoint can be fired from any page the user visits
// (an image, a redirect). With no id_token_hint to show the request came from an
// app the user signed in to, the endpoint asks before ending the session
// (RP-Initiated Logout 1.0 §2); the link it offers carries a value only the
// browser holding the session cookie was shown.

var confirmLink = regexp.MustCompile(`href="([^"]+)"`)

// confirmedLogoutURL is target with the confirm value for cookie's session, as
// the confirmation page's link would carry it.
func confirmedLogoutURL(target string, cookie *http.Cookie) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + "confirm=" + logoutConfirmToken(cookie.Value)
}

func TestEndSession_WithoutAHintAsksBeforeSigningOut(t *testing.T) {
	r, sessions, cookies := newLogoutEngine(t, nil)
	issued, err := sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	cookie := cookies.Issue(issued.RefreshToken, issued.ExpiresAt)
	alive := func() bool {
		resolved, _ := cookies.Resolve(context.Background(), cookie.Value)
		return resolved != nil
	}
	get := func(target string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if c != nil {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// A request that merely arrives with the cookie ends nothing.
	w := get("/api/v1/oidc/logout?state=abc", cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign out") {
		t.Fatalf("no-hint request with a session = %d; want a 200 page asking to confirm", w.Code)
	}
	if !alive() {
		t.Fatal("the session ended before anyone confirmed")
	}
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		t.Errorf("the page cleared or set a cookie before confirmation: %q", sc)
	}
	body := w.Body.String()
	if strings.Contains(strings.ToLower(body), "<script") || strings.Contains(body, cookie.Value) {
		t.Error("the confirmation page carries a script or the session cookie's value")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q; want no scripts and no framing", csp)
	}

	// A wrong value, or one minted for someone else's cookie, ends nothing.
	if w := get("/api/v1/oidc/logout?confirm=deadbeef", cookie); !strings.Contains(w.Body.String(), "Sign out") || !alive() {
		t.Error("a made-up confirm value ended the session")
	}
	other := &http.Cookie{Name: cookie.Name, Value: "someone-elses-cookie-value"}
	if w := get("/api/v1/oidc/logout?confirm="+logoutConfirmToken(other.Value), cookie); !strings.Contains(w.Body.String(), "Sign out") || !alive() {
		t.Error("a confirm value minted for another cookie ended the session")
	}

	// The link on the page is the confirmation.
	m := confirmLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the page offers no link to confirm: %q", body)
	}
	w = get(html.UnescapeString(m[1]), cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "You are signed out") {
		t.Fatalf("confirmed = %d; want the signed-out page", w.Code)
	}
	if alive() {
		t.Error("the confirmed sign-out left the session alive")
	}
}

// With a verified hint the request is vouched for and is not asked about; the
// hint tests (TestLogout_AnExpiredHintStillLogsOut and the verifier harness)
// cover that. With no session there is nothing to end, so nothing is asked.
func TestEndSession_WithoutASessionIsNotAsked(t *testing.T) {
	r, _, _ := newLogoutEngine(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout", nil))
	if !strings.Contains(w.Body.String(), "You are signed out") {
		t.Errorf("no session, no hint: want the signed-out page at once, got %d", w.Code)
	}
}
