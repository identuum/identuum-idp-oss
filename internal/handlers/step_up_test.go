package handlers

// step_up_test.go — THE-HONEST-ACR: the TOTP step-up ceremony uplifts the
// SAME session only after a verified code (RecordACRUplift with the TOTP
// rung), and never otherwise.

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

type fakeStepUpResolver struct {
	resolved *service.CookieSessionLookupResult
}

func (f *fakeStepUpResolver) Read(r *http.Request) (string, bool) {
	v := r.Header.Get("X-Test-Session")
	return v, v != ""
}

func (f *fakeStepUpResolver) Resolve(_ context.Context, v string) (*service.CookieSessionLookupResult, error) {
	if v != "live" || f.resolved == nil {
		return nil, errors.New("no session")
	}
	return f.resolved, nil
}

type fakeStepUpVerifier struct{ accept string }

func (f fakeStepUpVerifier) Verify(_ context.Context, _ *domain.User, code string) error {
	if code == f.accept {
		return nil
	}
	return service.ErrMFAInvalid
}

type captureUplift struct {
	calls     int
	sessionID uuid.UUID
	at        time.Time
	value     string
}

func (c *captureUplift) RecordACRUplift(_ context.Context, sessionID uuid.UUID, at time.Time, value string) error {
	c.calls++
	c.sessionID, c.at, c.value = sessionID, at, value
	return nil
}

func newStepUpEngine(t *testing.T, mfaEnrolled bool) (*gin.Engine, *captureUplift, *domain.Session) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	sess := &domain.Session{ID: uuid.New(), UserID: uuid.New(), IsValid: true, Acr: service.ACRPassword, Amr: []string{service.AMRPassword}}
	user := &domain.User{ID: sess.UserID, Email: "alice@example.com", MFAEnabled: mfaEnrolled}
	rec := &captureUplift{}
	r := gin.New()
	RegisterStepUpRoutes(r, StepUpHandlerDeps{
		CookieSession: &fakeStepUpResolver{resolved: &service.CookieSessionLookupResult{Session: sess, User: user}},
		Verifier:      fakeStepUpVerifier{accept: "123456"},
		Sessions:      rec,
		Now:           func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) },
	})
	return r, rec, sess
}

func postStepUp(r *gin.Engine, session, code, returnTo string) *httptest.ResponseRecorder {
	form := url.Values{"totp_code": {code}, "return_to": {returnTo}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/step-up", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if session != "" {
		req.Header.Set("X-Test-Session", session)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestStepUpForm_RequiresSessionAndRendersCode(t *testing.T) {
	r, _, _ := newStepUpEngine(t, true)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status = %d, want 401", w.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up?return_to="+url.QueryEscape("/api/v1/oauth/authorize?client_id=c&acr_values=x")+"&error=invalid_code", nil)
	req.Header.Set("X-Test-Session", "live")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`name="totp_code"`, `name="return_to" value="/api/v1/oauth/authorize?client_id=c&amp;acr_values=x"`, `data-error="invalid_code"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form lacks %s:\n%s", want, body)
		}
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

// RULE: ACR-HONEST-1 — uplift writes LastACRUpliftAt (RecordACRUplift with
// the TOTP rung on the SAME session) exactly when the code verifies.
func TestStepUpSubmit_VerifiedCodeRecordsUplift(t *testing.T) {
	r, rec, sess := newStepUpEngine(t, true)
	w := postStepUp(r, "live", "123456", "/api/v1/oauth/authorize?client_id=c")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/api/v1/oauth/authorize?client_id=c" {
		t.Fatalf("status=%d location=%q, want 303 back to return_to", w.Code, w.Header().Get("Location"))
	}
	if rec.calls != 1 {
		t.Fatalf("RecordACRUplift calls = %d, want 1", rec.calls)
	}
	if rec.sessionID != sess.ID || rec.value != service.ACRMFA || rec.at.IsZero() {
		t.Fatalf("uplift = (%s, %s, %v), want (%s, %s, non-zero)", rec.sessionID, rec.value, rec.at, sess.ID, service.ACRMFA)
	}
	// The domain view of what was written: EffectiveACR/AMR now carry TOTP.
	sess.RecordACRUplift(rec.at, rec.value)
	if sess.EffectiveACR() != service.ACRMFA || sess.LastACRUpliftAt == nil {
		t.Fatalf("EffectiveACR=%q LastACRUpliftAt=%v after uplift", sess.EffectiveACR(), sess.LastACRUpliftAt)
	}
	if amr := sess.EffectiveAMR(); len(amr) != 2 || amr[1] != service.AMROTP {
		t.Fatalf("EffectiveAMR = %v, want [pwd otp]", amr)
	}
}

func TestStepUpSubmit_WrongCodeNeverUplifts(t *testing.T) {
	r, rec, _ := newStepUpEngine(t, true)
	w := postStepUp(r, "live", "000000", "/api/v1/oauth/authorize?client_id=c")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/api/v1/auth/step-up?error=invalid_code&return_to=") {
		t.Fatalf("status=%d location=%q, want 303 back to the form with error=invalid_code", w.Code, w.Header().Get("Location"))
	}
	if rec.calls != 0 {
		t.Fatalf("RecordACRUplift calls = %d, want 0 (wrong code)", rec.calls)
	}
}

func TestStepUpSubmit_NotEnrolledRefused(t *testing.T) {
	r, rec, _ := newStepUpEngine(t, false)
	w := postStepUp(r, "live", "123456", "/x")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "mfa_not_enrolled") {
		t.Fatalf("status=%d body=%s, want 403 mfa_not_enrolled", w.Code, w.Body.String())
	}
	if rec.calls != 0 {
		t.Fatalf("RecordACRUplift calls = %d, want 0", rec.calls)
	}
}

func TestStepUpSubmit_NoSessionIs401(t *testing.T) {
	r, rec, _ := newStepUpEngine(t, true)
	if w := postStepUp(r, "", "123456", "/x"); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if rec.calls != 0 {
		t.Fatalf("RecordACRUplift calls = %d, want 0", rec.calls)
	}
}

// Off-origin return_to is dropped (open-redirect defence), the uplift still
// lands, and the browser goes to "/".
func TestStepUpSubmit_OffOriginReturnToDropped(t *testing.T) {
	r, rec, _ := newStepUpEngine(t, true)
	w := postStepUp(r, "live", "123456", "https://evil.example/cb")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("status=%d location=%q, want 303 /", w.Code, w.Header().Get("Location"))
	}
	if rec.calls != 1 {
		t.Fatalf("RecordACRUplift calls = %d, want 1", rec.calls)
	}
}

// Routes do not register without the three required seams.
func TestRegisterStepUpRoutes_RequiresDeps(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterStepUpRoutes(r, StepUpHandlerDeps{
		CookieSession: &fakeStepUpResolver{},
		Verifier:      fakeStepUpVerifier{},
		Now:           func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) },
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/step-up", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (unmounted without Sessions)", w.Code)
	}
}
