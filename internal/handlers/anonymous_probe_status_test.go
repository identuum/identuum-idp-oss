package handlers

// OSS-HARDEN item 4 (owner ruling 2026-10-01): under the step-status opt-in
// (X-Identuum-Login-Step-Status: 200), the console's session probe
// (GET /api/v1/validate) and the browser refresh answer a caller who presents
// NO credential 200 {"authenticated":false} — never a session, a cookie or a
// token. Without the opt-in, and for every other refusal, the answers are
// unchanged.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const signedOutBody = `{"authenticated":false}`

func validateRequest(r *gin.Engine, cookie, stepStatus string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "access_token", Value: cookie})
	}
	if stepStatus != "" {
		req.Header.Set(LoginStepStatusHeader, stepStatus)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestValidate_AnonymousProbe(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		TokenVerifier: fakeValidateVerifier{err: domain.ErrInvalidRequest},
		SessionLookup: fakeSessionByID{},
		UserLookup:    fakeUserByID{},
	})

	def := validateRequest(r, "", "")
	if def.Code != http.StatusUnauthorized {
		t.Fatalf("default, no credential: status %d, want 401", def.Code)
	}
	const wantDefault = `{"error":"unauthorized","reason":"missing_credential"}`
	if def.Body.String() != wantDefault {
		t.Fatalf("default body %q, want today's %q", def.Body.String(), wantDefault)
	}

	opt := validateRequest(r, "", "200")
	if opt.Code != http.StatusOK || opt.Body.String() != signedOutBody {
		t.Fatalf("opt-in, no credential: status %d body %q, want 200 %q", opt.Code, opt.Body.String(), signedOutBody)
	}
	if len(opt.Result().Cookies()) != 0 {
		t.Fatal("the signed-out answer set a cookie")
	}

	// A credential that does not verify is a verdict, not a signed-out caller:
	// 401 with or without the opt-in.
	for _, v := range []string{"", "200"} {
		if w := validateRequest(r, "a-cookie-that-does-not-verify", v); w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid credential, header %q: status %d, want 401", v, w.Code)
		}
	}
	// Only the exact value opts in.
	if w := validateRequest(r, "", "1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("header value 1: status %d, want 401", w.Code)
	}
}

func TestBrowserRefresh_AnonymousProbe(t *testing.T) {
	_, repo, minter, issued := browserRefreshFixture(t)
	sessions := service.NewUserSessionService(nil, repo, service.UserSessionServiceOptions{})
	user := &domain.User{ID: issued.Session.UserID, Role: domain.RoleOrgUser, Email: "fixture@example.test"}
	tokens := service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{
		Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute, Minter: minter,
	})
	e := gin.New()
	e.POST("/refresh", HandleBrowserSessionRefresh(AuthSessionsHandlerDeps{
		UserSession: sessions, UserToken: tokens,
		UserLookup: &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{user.ID: user}},
	}))
	post := func(cookie, stepStatus string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookie})
		}
		if stepStatus != "" {
			req.Header.Set(LoginStepStatusHeader, stepStatus)
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		return w
	}

	def := post("", "")
	const wantDefault = `{"reason":"missing_refresh_credential"}`
	if def.Code != http.StatusUnauthorized || def.Body.String() != wantDefault {
		t.Fatalf("default, no cookie: status %d body %q, want 401 %q", def.Code, def.Body.String(), wantDefault)
	}
	opt := post("", "200")
	if opt.Code != http.StatusOK || opt.Body.String() != signedOutBody {
		t.Fatalf("opt-in, no cookie: status %d body %q, want 200 %q", opt.Code, opt.Body.String(), signedOutBody)
	}
	if len(opt.Result().Cookies()) != 0 {
		t.Fatal("the signed-out refresh answer set a cookie")
	}
	// A refresh cookie that is refused stays a 401 with or without the opt-in.
	for _, v := range []string{"", "200"} {
		if w := post("not-a-refresh-token", v); w.Code != http.StatusUnauthorized {
			t.Fatalf("refused cookie, header %q: status %d, want 401", v, w.Code)
		}
	}
}
