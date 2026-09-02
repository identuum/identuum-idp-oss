package handlers

// step_up_passkey_test.go — THE-PHISHING-RESISTANT-ACR: the passkey step-up
// uplifts the SAME browser session to the phishing-resistant rung only after
// an assertion that verifies FOR THAT USER; a failed or foreign assertion
// writes nothing.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// fakeAsserter: BeginAssertion mints fixed options; FinishLogin answers per
// the configured mode.
type fakeAsserter struct {
	noCredentials bool
	finishErr     error
	finishUser    *domain.User
	beginCalls    int
}

func (f *fakeAsserter) BeginAssertion(_ context.Context, user *domain.User) (any, string, error) {
	f.beginCalls++
	if f.noCredentials {
		return nil, "", service.ErrWebAuthnNoCredentials
	}
	return map[string]any{
		"challenge":        "Y2hhbGxlbmdl",
		"rpId":             "localhost",
		"allowCredentials": []map[string]any{{"type": "public-key", "id": "Y3JlZC0x"}},
		"userVerification": "preferred",
	}, "ceremony-1", nil
}

func (f *fakeAsserter) FinishLogin(_ context.Context, sessionID string, _ *http.Request) (*domain.WebAuthnCredential, *domain.User, bool, error) {
	if sessionID != "ceremony-1" {
		return nil, nil, false, service.ErrWebAuthnSessionInvalid
	}
	if f.finishErr != nil {
		return nil, nil, false, f.finishErr
	}
	return &domain.WebAuthnCredential{}, f.finishUser, true, nil
}

func newPasskeyStepUpEngine(t *testing.T, asserter *fakeAsserter) (*gin.Engine, *captureUplift, *domain.Session, *domain.User) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	sess := &domain.Session{ID: uuid.New(), UserID: uuid.New(), IsValid: true, Acr: service.ACRPassword, Amr: []string{service.AMRPassword}}
	user := &domain.User{ID: sess.UserID, Email: "alice@example.com"}
	if asserter.finishUser == nil && asserter.finishErr == nil {
		asserter.finishUser = user
	}
	rec := &captureUplift{}
	r := gin.New()
	RegisterPasskeyStepUpRoutes(r, PasskeyStepUpHandlerDeps{
		CookieSession: &fakeStepUpResolver{resolved: &service.CookieSessionLookupResult{Session: sess, User: user}},
		WebAuthn:      asserter,
		Sessions:      rec,
		Now:           func() time.Time { return time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC) },
	})
	return r, rec, sess, user
}

func postPasskeyFinish(r *gin.Engine, session, ceremony, returnTo string) *httptest.ResponseRecorder {
	q := url.Values{}
	if ceremony != "" {
		q.Set("session_id", ceremony)
	}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up/passkey?"+q.Encode(), strings.NewReader(`{"id":"x","rawId":"eA","type":"public-key","response":{}}`))
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set("X-Test-Session", session)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestPasskeyStepUpPage_RendersCeremonyForTheSessionUser(t *testing.T) {
	r, _, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up/passkey", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status = %d, want 401", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up/passkey?return_to="+url.QueryEscape(`/api/v1/oauth/authorize?client_id=c&acr_values=x"</script>`), nil)
	req.Header.Set("X-Test-Session", "live")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"challenge":"Y2hhbGxlbmdl"`, `var CEREMONY = "ceremony-1"`, `navigator.credentials.get`, `/api/v1/auth/step-up/passkey?session_id=`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, `</script>"`) || !strings.Contains(body, `\u003c/script\u003e`) {
		t.Errorf("return_to must be JS-escaped inside the script block:\n%s", body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestPasskeyStepUpPage_NotEnrolledRefused(t *testing.T) {
	r, rec, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{noCredentials: true})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up/passkey", nil)
	req.Header.Set("X-Test-Session", "live")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "passkey_not_enrolled") {
		t.Fatalf("status=%d body=%s, want 403 passkey_not_enrolled", w.Code, w.Body.String())
	}
	if rec.calls != 0 {
		t.Fatalf("uplift calls = %d, want 0", rec.calls)
	}
}

// RULE: ACR-HONEST-2 — the uplift is recorded exactly when the assertion
// verifies for the session's own user.
func TestPasskeyStepUpFinish_VerifiedAssertionRecordsPhishingResistantUplift(t *testing.T) {
	r, rec, sess, _ := newPasskeyStepUpEngine(t, &fakeAsserter{})
	w := postPasskeyFinish(r, "live", "ceremony-1", "/api/v1/oauth/authorize?client_id=c")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"return_to":"/api/v1/oauth/authorize?client_id=c"`) {
		t.Fatalf("status=%d body=%s, want 200 with return_to", w.Code, w.Body.String())
	}
	if rec.calls != 1 || rec.sessionID != sess.ID || rec.value != service.ACRPhishingResistant || rec.at.IsZero() {
		t.Fatalf("uplift = calls %d (%s, %s, %v), want 1 (%s, phishing-resistant, non-zero)", rec.calls, rec.sessionID, rec.value, rec.at, sess.ID)
	}
	sess.RecordACRUplift(rec.at, rec.value)
	if sess.EffectiveACR() != service.ACRPhishingResistant || sess.LastACRUpliftAt == nil {
		t.Fatalf("EffectiveACR=%q LastACRUpliftAt=%v", sess.EffectiveACR(), sess.LastACRUpliftAt)
	}
}

func TestPasskeyStepUpFinish_FailedAssertionWritesNothing(t *testing.T) {
	r, rec, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{finishErr: service.ErrWebAuthnAssertionInvalid})
	w := postPasskeyFinish(r, "live", "ceremony-1", "/x")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_assertion") {
		t.Fatalf("status=%d body=%s, want 401 invalid_assertion", w.Code, w.Body.String())
	}
	if rec.calls != 0 {
		t.Fatalf("uplift calls = %d, want 0", rec.calls)
	}
}

func TestPasskeyStepUpFinish_AnotherUsersAssertionWritesNothing(t *testing.T) {
	other := &domain.User{ID: uuid.New(), Email: "mallory@example.com"}
	r, rec, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{finishUser: other})
	w := postPasskeyFinish(r, "live", "ceremony-1", "/x")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401 (assertion by another user)", w.Code)
	}
	if rec.calls != 0 {
		t.Fatalf("uplift calls = %d, want 0", rec.calls)
	}
}

func TestPasskeyStepUpFinish_RequiresSessionAndCeremony(t *testing.T) {
	r, rec, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{})
	if w := postPasskeyFinish(r, "", "ceremony-1", "/x"); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status = %d, want 401", w.Code)
	}
	if w := postPasskeyFinish(r, "live", "", "/x"); w.Code != http.StatusBadRequest {
		t.Fatalf("no ceremony id: status = %d, want 400", w.Code)
	}
	if w := postPasskeyFinish(r, "live", "ceremony-9", "/x"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown ceremony id: status = %d, want 401", w.Code)
	}
	if rec.calls != 0 {
		t.Fatalf("uplift calls = %d, want 0", rec.calls)
	}
}

func TestPasskeyStepUpFinish_OffOriginReturnToDropped(t *testing.T) {
	r, rec, _, _ := newPasskeyStepUpEngine(t, &fakeAsserter{})
	w := postPasskeyFinish(r, "live", "ceremony-1", "https://evil.example/cb")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"return_to":"/"`) {
		t.Fatalf("status=%d body=%s, want 200 return_to /", w.Code, w.Body.String())
	}
	if rec.calls != 1 {
		t.Fatalf("uplift calls = %d, want 1", rec.calls)
	}
}

func TestRegisterPasskeyStepUpRoutes_RequiresDeps(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterPasskeyStepUpRoutes(r, PasskeyStepUpHandlerDeps{
		CookieSession: &fakeStepUpResolver{},
		WebAuthn:      &fakeAsserter{},
		Now:           func() time.Time { return time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC) },
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up/passkey", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (unmounted without Sessions)", w.Code)
	}
	_ = errors.New
}
