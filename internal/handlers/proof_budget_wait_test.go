package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// v0.9.6 left one route family answering a spent wrong-code budget as a
// wrong code: step-up and the other second-factor proofs (MFA disable,
// recovery-code regenerate, skip consent). They now give sign-in's wait
// answer: the JSON routes 429 login_throttled with Retry-After, and the
// step-up browser form, like the browser sign-in, a 303 back to its page with
// error=login_throttled and Retry-After, where the page says to wait.

type waitingVerifier struct{}

func (waitingVerifier) Verify(context.Context, *domain.User, string) error {
	return &service.LoginThrottledError{RetryAfter: 90 * time.Second, Bounded: true}
}

func TestStepUpSubmit_ASpentBudgetSaysToWait(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	sess := &domain.Session{ID: uuid.New(), UserID: uuid.New(), IsValid: true, Acr: service.ACRPassword}
	user := &domain.User{ID: sess.UserID, Email: "alice@example.com", MFAEnabled: true}
	rec := &captureUplift{}
	r := gin.New()
	RegisterStepUpRoutes(r, StepUpHandlerDeps{
		CookieSession: &fakeStepUpResolver{resolved: &service.CookieSessionLookupResult{Session: sess, User: user}},
		Verifier:      waitingVerifier{},
		Sessions:      rec,
		Now:           func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
	})
	w := postStepUp(r, "live", "123456", "/api/v1/oauth/authorize?client_id=c")
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.Contains(loc, "error=login_throttled") {
		t.Fatalf("step-up at a spent budget = %d %q; want 303 with error=login_throttled", w.Code, loc)
	}
	if secs, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || secs != 90 {
		t.Errorf("Retry-After = %q; want 90", w.Header().Get("Retry-After"))
	}
	if rec.calls != 0 {
		t.Error("a refused step-up recorded an uplift")
	}
	page := httptest.NewRequest(http.MethodGet, loc, nil)
	page.Header.Set("X-Test-Session", "live")
	pw := httptest.NewRecorder()
	r.ServeHTTP(pw, page)
	if !strings.Contains(pw.Body.String(), "Too many attempts") {
		t.Errorf("the step-up page does not say to wait")
	}
}

// The JSON proof routes on the real service: three wrong codes spend a
// budget of three, then regenerate and disable answer 429 with Retry-After.
func TestMFAProofRoutes_ASpentBudgetSaysToWait(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	userID := uuid.New()
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{UserID: userID, Role: domain.RoleOrgUser}))
	users := newRecoveryStubUserRepo()
	mfaSvc := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: recoveryPendingRepoStub{}, Users: users, Issuer: "Identuum", Cipher: identityMFACipher{}, Replay: testReplayGuardForHandlers(),
	}, service.MFAEnrollmentServiceOptions{ProofFailures: service.NewTOTPFailureBudget(3, 15*time.Minute, nil)})
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{MFAEnrollment: mfaSvc})
	eng := recoveryTestEngine{r: r, userRepo: users}
	seedRecoveryUser(eng, userID, true)
	for i := 0; i < 3; i++ {
		recoveryReqWithCode(t, eng, "000000")
	}
	for name, path := range map[string]string{"regenerate": "/api/v1/me/mfa/recovery-codes/regenerate", "disable": "/api/v1/me/mfa/disable"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"code":"`+recoveryTOTPNow(t)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"login_throttled"`) || w.Header().Get("Retry-After") == "" {
			t.Errorf("%s with the right code at a spent budget = %d %s; want 429 login_throttled with Retry-After", name, w.Code, w.Body.String())
		}
	}
}

type waitingProver struct{}

func (waitingProver) ProveTOTP(context.Context, uuid.UUID, string) error {
	return &service.LoginThrottledError{RetryAfter: 30 * time.Second, Bounded: true}
}

func TestSkipConsentProof_ASpentBudgetSaysToWait(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{UserID: uuid.New()}))
	passed := true
	r.POST("/x", func(c *gin.Context) {
		passed = requireSkipConsentProof(c, ClientsHandlerDeps{SkipConsentProver: waitingProver{}}, "123456")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	if passed {
		t.Fatal("a spent budget passed the proof")
	}
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"login_throttled"`) || w.Header().Get("Retry-After") != "30" {
		t.Errorf("skip-consent proof at a spent budget = %d %s Retry-After %q; want 429 login_throttled, 30", w.Code, w.Body.String(), w.Header().Get("Retry-After"))
	}
}
