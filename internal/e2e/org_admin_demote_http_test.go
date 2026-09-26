//go:build integration

// Package e2e — OSS-DEMOTE: a role change or a disable through
// PUT /api/v1/users/:id takes effect on the user's next request, for every
// credential the user holds.
//
// Measured before the fix (OSS-DEMOTE item 1): the bearer principal's role
// and scopes come only from the token's claims (auth/jwt_verifier.go
// claimsToPrincipal), and the per-request session check (mw/bearer.go) reads
// users.banned and deleted_at but never users.role. So a demoted org_admin
// kept org_admin rights until its access token expired (one hour), while a
// disabled one was already refused. The browser's access_token cookie is the
// same JWT, lifted to a Bearer header by the /bff boundary
// (pkg/uiserve/uiserve.go), so the Bearer case below is also the cookie case.
//
// The test composes the real bearer middleware, the real users and session
// routes, and the real services and pgx repositories, and signs B in for
// real: a session plus a session-bound access token and refresh token.
// Tokens are never printed.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const demoteIssuer = "http://localhost:7113"

type demoteWorld struct {
	t        *testing.T
	ctx      context.Context
	repos    *postgres.Repositories
	org      uuid.UUID
	sessions *service.UserSessionService
	tokens   *service.UserTokenService
	api      *gin.Engine // bearer middleware + users routes
	authAPI  *gin.Engine // session routes (refresh, validate)
}

func demoteSetup(t *testing.T) *demoteWorld {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)

	keySvc := service.NewKeyService(repos.Key)
	if active, err := keySvc.ListActive(ctx); err != nil {
		t.Fatalf("ListActive keys: %v", err)
	} else if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{Algorithm: string(domain.KeyAlgorithmEdDSA), State: domain.KeyStateActive}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	tokens := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: demoteIssuer})
	verifier := auth.NewRepositoryVerifier(nil, repos.Key, auth.VerifierOptions{ExpectedIssuer: demoteIssuer})

	gin.SetMode(gin.ReleaseMode)
	api := gin.New()
	api.Use(mw.BearerPrincipal(nil, verifier, repos.Session, service.NewTokenRevocationService(nil, repos.TokenRevocation)))
	handlers.RegisterUsersRoutes(api, handlers.UsersHandlerDeps{
		UserService:         service.NewUserService(nil, repos.User),
		UserRepo:            repos.User,
		SessionRevoker:      sessions,
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
	})
	authAPI := gin.New()
	handlers.RegisterAuthSessionRoutes(authAPI, handlers.AuthSessionsHandlerDeps{
		LocalLogin:    service.NewLocalLoginService(nil, repos.User, sessions, nil),
		UserSession:   sessions,
		UserToken:     tokens,
		UserLookup:    repos.User,
		SessionLookup: repos.Session,
		TokenVerifier: verifier,
	})
	return &demoteWorld{t: t, ctx: ctx, repos: repos, org: org.ID, sessions: sessions, tokens: tokens, api: api, authAPI: authAPI}
}

func (w *demoteWorld) orgAdmin() *domain.User {
	w.t.Helper()
	u, err := w.repos.User.Create(w.ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: w.org,
		Email:          strings.ToLower("e2e-demote-" + uuid.NewString() + "@example.invalid"),
		PasswordHash:   "dm-" + uuid.NewString(),
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		w.t.Fatalf("seed org_admin: %v", err)
	}
	return u
}

// signIn opens a real session for u and returns its session-bound access
// token and refresh token (never printed).
func (w *demoteWorld) signIn(u *domain.User) (access, refresh string) {
	w.t.Helper()
	issued, err := w.sessions.CreateUserSession(w.ctx, service.CreateUserSessionInput{UserID: u.ID})
	if err != nil {
		w.t.Fatalf("create session: %v", err)
	}
	tok, err := w.tokens.IssueForSession(w.ctx, u, issued.Session)
	if err != nil {
		w.t.Fatalf("issue access token: %v", err)
	}
	return tok.AccessToken, issued.RefreshToken
}

func (w *demoteWorld) bearer(token, method, path, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = "localhost:7113"
	rec := httptest.NewRecorder()
	w.api.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// refreshThenAdminCall redeems the refresh token and, when a new access
// token comes back, uses it for one org_admin call. It returns the refresh
// status and the admin call's status (0 when no token was minted).
func (w *demoteWorld) refreshThenAdminCall(refresh string) (int, int) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", strings.NewReader(`{"refresh_token":"`+refresh+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "localhost:7113"
	rec := httptest.NewRecorder()
	w.authAPI.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		return rec.Code, 0
	}
	st, _ := w.bearer(tok, http.MethodGet, "/api/v1/users", "")
	return rec.Code, st
}

// After an org_admin demotes another org_admin, the demoted user's access
// token (the Bearer header and the browser cookie alike) and its refresh
// token carry no org_admin rights on the next request.
func TestE2E_OSS_ADemotedOrgAdminLosesAdminRightsAtOnce(t *testing.T) {
	w := demoteSetup(t)
	a, b := w.orgAdmin(), w.orgAdmin()
	aTok, _ := w.signIn(a)
	bTok, bRefresh := w.signIn(b)
	if st, body := w.bearer(bTok, http.MethodGet, "/api/v1/users", ""); st != http.StatusOK {
		t.Fatalf("b's admin call before the demotion = %d %s; want 200", st, body)
	}
	if st, body := w.bearer(aTok, http.MethodPut, "/api/v1/users/"+b.ID.String(), `{"role":"org_user"}`); st != http.StatusOK {
		t.Fatalf("a demotes b = %d %s; want 200", st, body)
	}
	if st, body := w.bearer(bTok, http.MethodGet, "/api/v1/users", ""); st != http.StatusUnauthorized {
		t.Errorf("b's pre-demotion access token on an org_admin call after the demotion = %d %s; want 401 (no old rights)", st, body)
	}
	if rst, adminSt := w.refreshThenAdminCall(bRefresh); rst == http.StatusOK && adminSt == http.StatusOK {
		t.Errorf("b's pre-demotion refresh token minted a token that still passes an org_admin call (refresh %d, admin %d)", rst, adminSt)
	}
	// a is unaffected.
	if st, body := w.bearer(aTok, http.MethodGet, "/api/v1/users", ""); st != http.StatusOK {
		t.Errorf("a's own admin call after demoting b = %d %s; want 200", st, body)
	}
}

// A disable is refused on the next request for every credential (it was
// already, through the session liveness check); it stays so.
func TestE2E_OSS_ADisabledOrgAdminIsRefusedAtOnce(t *testing.T) {
	w := demoteSetup(t)
	a, b := w.orgAdmin(), w.orgAdmin()
	aTok, _ := w.signIn(a)
	bTok, bRefresh := w.signIn(b)
	if st, body := w.bearer(aTok, http.MethodPut, "/api/v1/users/"+b.ID.String(), `{"active":false}`); st != http.StatusOK {
		t.Fatalf("a disables b = %d %s; want 200", st, body)
	}
	if st, body := w.bearer(bTok, http.MethodGet, "/api/v1/users", ""); st != http.StatusUnauthorized {
		t.Errorf("b's access token after the disable = %d %s; want 401", st, body)
	}
	if rst, adminSt := w.refreshThenAdminCall(bRefresh); rst == http.StatusOK || adminSt == http.StatusOK {
		t.Errorf("b's refresh token after the disable: refresh %d, admin %d; want refused", rst, adminSt)
	}
}
