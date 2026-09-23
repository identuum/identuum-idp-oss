//go:build integration

// Package e2e — PLAN-C-CLOSE (THE-UI-IN-THE-BINARY, 2026-09-23): DATABASE
// proofs for the browser-session boundary against the live pgx repositories.
// Every test here drives the real HTTP handlers (HandleBrowserSessionRefresh,
// HandleLogout) over a real Postgres, not a fake:
//
//   - rotation race: two concurrent browser refreshes with one refresh cookie
//     mint exactly ONE successor cookie, and that successor works;
//   - reuse after grace: the consumed predecessor is refused and the whole
//     session family is revoked in the database;
//   - outage: a store that cannot answer yields 503 refresh_unavailable, no
//     cookie, and the stored validator is unchanged (nothing rotated);
//   - logout: confirmed revocation (204, row revoked) versus an unreachable
//     store (503 revocation_unconfirmed, cookies still cleared);
//   - authentication facts: the refreshed access token carries the session's
//     original auth_time, acr and amr.
//
// Raw refresh and access tokens are never printed.
//
// Run: go test -tags integration -run PlanC -v ./internal/e2e/...
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type planCFixture struct {
	pool      *pgxpool.Pool
	repos     *postgres.Repositories
	sessions  *service.UserSessionService
	userToken *service.UserTokenService
	user      *domain.User
	issued    *service.IssuedUserSession
}

func newPlanCFixture(t *testing.T, ctx context.Context) *planCFixture {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())

	org := seedTestOrganization(t, ctx, repos)
	user, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          strings.ToLower("e2e-planc-" + uuid.NewString() + "@example.invalid"),
		PasswordHash:   "not-a-real-hash-" + uuid.NewString(),
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _ = repos.User.Delete(context.Background(), user.ID, user.OrganizationID) })

	keySvc := service.NewKeyService(repos.Key)
	if active, err := keySvc.ListActive(ctx); err != nil {
		t.Fatalf("ListActive keys: %v", err)
	} else if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{Algorithm: string(domain.KeyAlgorithmEdDSA), State: domain.KeyStateActive}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	issued, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{
		UserID: user.ID, Acr: "urn:identuum:acr:mfa", Amr: []string{"pwd", "otp"},
	})
	if err != nil || issued == nil || issued.RefreshToken == "" {
		t.Fatalf("CreateUserSession: %v", err)
	}
	return &planCFixture{
		pool: pool, repos: repos, sessions: sessions, user: user, issued: issued,
		userToken: service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: "http://localhost:7113"}),
	}
}

func (fx *planCFixture) refreshEngine(sessions *service.UserSessionService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	e := gin.New()
	e.POST("/refresh", handlers.HandleBrowserSessionRefresh(handlers.AuthSessionsHandlerDeps{
		UserSession: sessions, UserToken: fx.userToken, UserLookup: fx.repos.User,
	}))
	return e
}

func planCRefresh(e http.Handler, raw string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://localhost:7113/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: raw})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func planCCookie(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// closedPoolSessions is a session service whose store cannot answer: the
// same repositories over a pool that has been closed.
func (fx *planCFixture) closedPoolSessions(t *testing.T, ctx context.Context) *service.UserSessionService {
	t.Helper()
	dead, err := postgres.NewPool(ctx, testDBURL(t), nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	dead.Close()
	return service.NewUserSessionService(nil, postgres.NewPgxRepositories(dead, e2eSigningKeyCipher()).Session, service.UserSessionServiceOptions{})
}

func (fx *planCFixture) validatorHash(t *testing.T, ctx context.Context) string {
	t.Helper()
	s, err := fx.repos.Session.GetByID(ctx, fx.issued.Session.ID)
	if err != nil || s == nil || s.TokenValidatorHash == nil {
		t.Fatalf("GetByID: %v", err)
	}
	return *s.TokenValidatorHash
}

func TestE2E_PlanC_BrowserRefreshRace_OneSuccessor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fx := newPlanCFixture(t, ctx)
	e := fx.refreshEngine(fx.sessions)

	var wg sync.WaitGroup
	release := make(chan struct{})
	results := make([]*httptest.ResponseRecorder, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-release
			results[i] = planCRefresh(e, fx.issued.RefreshToken)
		}(i)
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	successors := []string{}
	for i, rec := range results {
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("racer %d: status %d, body %d bytes; want 204 with no body", i, rec.Code, rec.Body.Len())
		}
		if planCCookie(rec, "access_token") == "" {
			t.Fatalf("racer %d: no access cookie", i)
		}
		if v := planCCookie(rec, "refresh_token"); v != "" {
			if v == fx.issued.RefreshToken {
				t.Fatalf("racer %d: a predecessor refresh cookie was re-set", i)
			}
			successors = append(successors, v)
		}
	}
	if len(successors) != 1 {
		t.Fatalf("two concurrent refreshes minted %d successor refresh cookies; want exactly 1", len(successors))
	}
	if next := planCRefresh(e, successors[0]); next.Code != http.StatusNoContent {
		t.Fatalf("the one successor must itself refresh: status %d", next.Code)
	}
	active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.user.ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("after the race the family must be intact with one live session: %d (%v)", len(active), err)
	}
}

func TestE2E_PlanC_BrowserRefreshReuseAfterGrace_RevokesFamily(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fx := newPlanCFixture(t, ctx)
	e := fx.refreshEngine(fx.sessions)

	first := planCRefresh(e, fx.issued.RefreshToken)
	if first.Code != http.StatusNoContent || planCCookie(first, "refresh_token") == "" {
		t.Fatalf("first refresh: status %d", first.Code)
	}
	if _, err := fx.pool.Exec(ctx, `UPDATE sessions SET prev_rotated_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-30*time.Second), fx.issued.Session.ID); err != nil {
		t.Fatalf("age prev_rotated_at past grace: %v", err)
	}
	replay := planCRefresh(e, fx.issued.RefreshToken)
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), "refresh_refused") || len(replay.Result().Cookies()) != 0 {
		t.Fatalf("replay after grace: status %d body %q cookies %d; want 401 refresh_refused and none", replay.Code, replay.Body.String(), len(replay.Result().Cookies()))
	}
	active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.user.ID)
	if err != nil {
		t.Fatalf("ListActiveByUserID: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("reuse must revoke the whole family in the database; still active=%d", len(active))
	}
}

func TestE2E_PlanC_BrowserRefreshOutage_503NoRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fx := newPlanCFixture(t, ctx)
	before := fx.validatorHash(t, ctx)

	rec := planCRefresh(fx.refreshEngine(fx.closedPoolSessions(t, ctx)), fx.issued.RefreshToken)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "refresh_unavailable") || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("refresh with the store down: status %d body %q cookies %d; want 503 refresh_unavailable and none", rec.Code, rec.Body.String(), len(rec.Result().Cookies()))
	}
	if after := fx.validatorHash(t, ctx); after != before {
		t.Fatal("an outage must not rotate the stored refresh credential")
	}
	// The untouched credential still refreshes once the store answers.
	if ok := planCRefresh(fx.refreshEngine(fx.sessions), fx.issued.RefreshToken); ok.Code != http.StatusNoContent {
		t.Fatalf("after the outage the same refresh cookie must still work: status %d", ok.Code)
	}
}

func planCLogout(e http.Handler, refresh string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://localhost:7113/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refresh})
	req.Header.Set("X-Requested-With", "identuum-ui")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func (fx *planCFixture) logoutEngine(sessions *service.UserSessionService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	e := gin.New()
	e.POST("/api/v1/auth/logout", handlers.HandleLogout(handlers.AuthSessionsHandlerDeps{UserSession: sessions}))
	return e
}

func planCCleared(rec *httptest.ResponseRecorder) bool {
	n := 0
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "access_token=;") || strings.HasPrefix(sc, "refresh_token=;") {
			n++
		}
	}
	return n == 2
}

func TestE2E_PlanC_LogoutConfirmedVersusUnconfirmed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("confirmed", func(t *testing.T) {
		fx := newPlanCFixture(t, ctx)
		// Only the refresh cookie: the access cookie has expired.
		rec := planCLogout(fx.logoutEngine(fx.sessions), fx.issued.RefreshToken)
		if rec.Code != http.StatusNoContent || !planCCleared(rec) || rec.Header().Get(handlers.LogoutUnconfirmedHeader) != "" {
			t.Fatalf("confirmed logout: status %d cleared %v marker %q; want 204, both cleared, no marker", rec.Code, planCCleared(rec), rec.Header().Get(handlers.LogoutUnconfirmedHeader))
		}
		active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.user.ID)
		if err != nil || len(active) != 0 {
			t.Fatalf("a confirmed logout must revoke the session in the database: active=%d (%v)", len(active), err)
		}
	})

	t.Run("unconfirmed", func(t *testing.T) {
		fx := newPlanCFixture(t, ctx)
		rec := planCLogout(fx.logoutEngine(fx.closedPoolSessions(t, ctx)), fx.issued.RefreshToken)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "revocation_unconfirmed") || !planCCleared(rec) {
			t.Fatalf("logout with the store down: status %d body %q cleared %v; want 503 revocation_unconfirmed with both cookies cleared", rec.Code, rec.Body.String(), planCCleared(rec))
		}
		active, err := fx.repos.Session.ListActiveByUserID(ctx, fx.user.ID)
		if err != nil || len(active) != 1 {
			t.Fatalf("an unconfirmed logout revoked nothing and must say so: active=%d (%v)", len(active), err)
		}
	})
}

func TestE2E_PlanC_BrowserRefreshKeepsAuthenticationFacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fx := newPlanCFixture(t, ctx)
	stored, err := fx.repos.Session.GetByID(ctx, fx.issued.Session.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // a refresh a second later must not move auth_time
	rec := planCRefresh(fx.refreshEngine(fx.sessions), fx.issued.RefreshToken)
	access := planCCookie(rec, "access_token")
	if rec.Code != http.StatusNoContent || access == "" {
		t.Fatalf("refresh: status %d", rec.Code)
	}
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatal("access cookie is not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal("access token payload is not base64url")
	}
	var claims struct {
		AuthTime int64    `json:"auth_time"`
		ACR      string   `json:"acr"`
		AMR      []string `json:"amr"`
		SID      string   `json:"session_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal("access token payload is not JSON")
	}
	if claims.AuthTime != stored.EffectiveAuthTime().Unix() || claims.ACR != stored.EffectiveACR() || !reflect.DeepEqual(claims.AMR, stored.EffectiveAMR()) {
		t.Fatalf("refreshed token authentication facts: auth_time=%d acr=%q amr=%v; the session's are auth_time=%d acr=%q amr=%v",
			claims.AuthTime, claims.ACR, claims.AMR, stored.EffectiveAuthTime().Unix(), stored.EffectiveACR(), stored.EffectiveAMR())
	}
	if claims.ACR != "urn:identuum:acr:mfa" || !reflect.DeepEqual(claims.AMR, []string{"pwd", "otp"}) {
		t.Fatalf("premise: the session was created with acr mfa and amr [pwd otp]; the token carries acr=%q amr=%v", claims.ACR, claims.AMR)
	}
	if claims.SID != fx.issued.Session.ID.String() {
		t.Fatal("the refreshed token must belong to the same session")
	}
}
