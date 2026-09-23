package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type logoutSecurityVerifier struct {
	err       error
	sessionID uuid.UUID
	calls     int
}

func TestLogoutSecurity_RefreshRevocationReportsStoreFailures(t *testing.T) {
	for _, failure := range []string{"none", "lookup", "revoke"} {
		t.Run(failure, func(t *testing.T) {
			repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
			h := newUnconfirmedHarness(t, repo)
			issued, err := h.sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uuid.New()})
			if err != nil {
				t.Fatal("could not create fixture session")
			}
			if failure == "lookup" {
				repo.selectorErr = errors.New("store unavailable")
			}
			if failure == "revoke" {
				repo.revokeErr = errors.New("store unavailable")
			}
			body, err := json.Marshal(map[string]string{"refresh_token": issued.RefreshToken})
			if err != nil {
				t.Fatal("could not encode fixture request")
			}
			e := gin.New()
			e.POST("/logout", HandleLogout(AuthSessionsHandlerDeps{UserSession: h.sessions, Audit: h.audit}))
			r := httptest.NewRequest(http.MethodPost, "/logout", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			want := http.StatusServiceUnavailable
			if failure == "none" {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Errorf("status = %d, want %d", w.Code, want)
			}
			if failure != "none" && w.Header().Get(LogoutUnconfirmedHeader) == "" {
				t.Error("missing unconfirmed revocation marker")
			}
			if failure == "none" {
				stored, err := repo.GetByID(context.Background(), issued.Session.ID)
				if err != nil || stored == nil || stored.RevokedAt == nil {
					t.Error("logout did not revoke the session")
				}
				if stored != nil && stored.PrevRotatedAt != nil {
					t.Error("logout rotated the refresh credential")
				}
			}
		})
	}
}

func (v *logoutSecurityVerifier) VerifyBearerToken(context.Context, string) (*domain.Principal, error) {
	v.calls++
	if v.err != nil {
		return nil, v.err
	}
	return &domain.Principal{SessionID: v.sessionID}, nil
}

func TestLogoutSecurity_SuccessAuditDoesNotDiscloseSessionID(t *testing.T) {
	repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
	h := newUnconfirmedHarness(t, repo)
	v := &logoutSecurityVerifier{sessionID: uuid.New()}
	e := gin.New()
	e.POST("/logout", HandleLogout(AuthSessionsHandlerDeps{UserSession: h.sessions, TokenVerifier: v, Audit: h.audit}))
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Header.Set("Authorization", "Bearer fixture")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", w.Code)
	}
	found := false
	for _, event := range h.audit.Events() {
		if event.Action != "user_session.logout" || event.Outcome != "success" {
			continue
		}
		found = true
		if _, present := event.Metadata["session_id"]; present {
			t.Error("logout audit contains a raw session identifier")
		}
		for _, value := range event.Metadata {
			if value == v.sessionID.String() {
				t.Error("logout audit exposes the session identifier under another key")
			}
		}
	}
	if !found {
		t.Error("successful logout audit missing")
	}
}

func TestLogoutSecurity_ImmediateStoreFailureIsNotSuccess(t *testing.T) {
	for _, failure := range []string{"verify", "revoke", "missing-verifier"} {
		t.Run(failure, func(t *testing.T) {
			repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
			h := newUnconfirmedHarness(t, repo)
			v := &logoutSecurityVerifier{sessionID: uuid.New()}
			deps := AuthSessionsHandlerDeps{UserSession: h.sessions, TokenVerifier: v, Audit: h.audit}
			if failure == "verify" {
				v.err = domain.AuthStoreUnavailable("test", errors.New("store unavailable"))
			}
			if failure == "revoke" {
				repo.revokeErr = errors.New("store unavailable")
			}
			if failure == "missing-verifier" {
				deps.TokenVerifier = nil
			}
			e := gin.New()
			e.POST("/logout", HandleLogout(deps))
			r := httptest.NewRequest(http.MethodPost, "/logout", nil)
			r.Header.Set("Authorization", "Bearer fixture")
			w := httptest.NewRecorder()
			e.ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", w.Code)
			}
			if w.Header().Get(LogoutUnconfirmedHeader) != "revocation_unconfirmed" {
				t.Error("missing unconfirmed revocation marker")
			}
			cleared := map[string]bool{}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Value == "" && cookie.MaxAge < 0 {
					cleared[cookie.Name] = true
				}
			}
			if !cleared["access_token"] || !cleared["refresh_token"] {
				t.Error("browser authentication cookies were not cleared")
			}
			for _, event := range h.audit.Events() {
				if event.Action == "user_session.logout" && event.Outcome == "success" {
					t.Error("failed revocation audited as success")
				}
			}
		})
	}
}

func TestLogoutSecurity_CookieWithoutCSRFProofRefusedBeforeVerification(t *testing.T) {
	repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
	h := newUnconfirmedHarness(t, repo)
	v := &logoutSecurityVerifier{sessionID: uuid.New()}
	e := gin.New()
	e.POST("/logout", HandleLogout(AuthSessionsHandlerDeps{UserSession: h.sessions, TokenVerifier: v, Audit: h.audit}))
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: "access_token", Value: "fixture"})
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if v.calls != 0 {
		t.Error("CSRF request reached token verification")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("CSRF refusal altered browser cookies")
	}
}

func TestLogoutSecurity_RefreshCookieCanEndSessionAfterAccessCookieExpires(t *testing.T) {
	repo := &failingSessionRepo{handlersSessionRepo: newHandlersSessionRepo()}
	h := newUnconfirmedHarness(t, repo)
	issued, err := h.sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: uuid.New()})
	if err != nil {
		t.Fatal("could not create fixture session")
	}
	e := gin.New()
	e.POST("/logout", HandleLogout(AuthSessionsHandlerDeps{UserSession: h.sessions, Audit: h.audit}))
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: "refresh_token", Value: issued.RefreshToken})
	r.Header.Set("X-Requested-With", "identuum-ui")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
	stored, err := repo.GetByID(context.Background(), issued.Session.ID)
	if err != nil || stored == nil || stored.RevokedAt == nil {
		t.Error("refresh cookie session was not revoked")
	}
}
