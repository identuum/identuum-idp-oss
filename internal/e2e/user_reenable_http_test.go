//go:build integration

// Package e2e — OSS-REENABLE-USER: an admin who disables a user must be able
// to read that user and enable them again, while the disabled user stays
// refused at login until then.
//
// Measured before the fix (PLAN-D-2, 2026-09-23): PgxUserRepository.GetByID
// filters banned = false, and every admin-management read went through it, so
// after PUT {"active": false} the user answered 404 on GET /api/v1/users/:id
// and PUT {"active": true} failed — a disabled user could never be enabled.
//
// The test composes the real Gin router, the real UserService and the real
// PgxUserRepository against the live compose Postgres (127.0.0.1:5513).
// Plaintext passwords, cookies and tokens are never printed.
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

func TestE2E_OSS_AdminDisablesThenReenablesUser(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.Session == nil {
		t.Fatal("repository factory returned nil User or Session repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-reenable-" + uuid.NewString() + "@example.invalid")
	plaintext := "re-" + uuid.NewString() + "-marker-not-printed"
	targetID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             targetID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

	// The acting org_admin of the same tenant, as the bearer middleware would
	// have established it.
	admin := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org.ID,
		Role:           domain.RoleOrgAdmin,
		Email:          "admin@example.invalid",
		Scope: strings.Join([]string{
			domain.ScopeUsersRead, domain.ScopeUsersUpdate, domain.ScopeUsersDisable,
		}, " "),
	}

	gin.SetMode(gin.ReleaseMode)
	adminAPI := gin.New()
	adminAPI.Use(mw.InjectPrincipalForTest(admin))
	handlers.RegisterUsersRoutes(adminAPI, handlers.UsersHandlerDeps{
		UserService: service.NewUserService(nil, repos.User),
		UserRepo:    repos.User,
	})

	keySvc := service.NewKeyService(repos.Key)
	if active, err := keySvc.ListActive(ctx); err != nil {
		t.Fatalf("ListActive keys: %v", err)
	} else if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{
			Algorithm: string(domain.KeyAlgorithmEdDSA),
			State:     domain.KeyStateActive,
		}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}
	const issuer = "http://localhost:7113"
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	authAPI := gin.New()
	handlers.RegisterAuthSessionRoutes(authAPI, handlers.AuthSessionsHandlerDeps{
		LocalLogin:    service.NewLocalLoginService(nil, repos.User, sessions, nil),
		UserSession:   sessions,
		UserToken:     service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: issuer}),
		UserLookup:    repos.User,
		SessionLookup: repos.Session,
		TokenVerifier: auth.NewRepositoryVerifier(nil, repos.Key, auth.VerifierOptions{ExpectedIssuer: issuer}),
	})

	call := func(engine *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Host = "localhost:7113"
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}
	login := func() int {
		body := `{"email":"` + email + `","password":"` + plaintext + `","remember_me":false}`
		return call(authAPI, http.MethodPost, "/api/v1/auth/login", body).Code
	}
	userPath := "/api/v1/users/" + created.ID.String()

	// The seeded user signs in before anything changes, and keeps the
	// credentials that login issued.
	body := `{"email":"` + email + `","password":"` + plaintext + `","remember_me":false}`
	first := call(authAPI, http.MethodPost, "/api/v1/auth/login", body)
	if first.Code != http.StatusOK {
		t.Fatalf("login before disable: status %d, want 200", first.Code)
	}
	var issued map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil {
		t.Fatalf("login before disable: parse JSON: %v", err)
	}
	oldRefresh, _ := issued["refresh_token"].(string)
	oldAccess := findCookieByName(first.Result().Cookies(), "access_token")
	if oldRefresh == "" || oldAccess == nil || oldAccess.Value == "" {
		t.Fatal("login before disable: refresh token or access cookie missing")
	}
	validate := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
		req.Host = "localhost:7113"
		req.AddCookie(&http.Cookie{Name: "access_token", Value: oldAccess.Value})
		w := httptest.NewRecorder()
		authAPI.ServeHTTP(w, req)
		return w.Code
	}
	if code := validate(); code != http.StatusOK {
		t.Fatalf("validate before disable: status %d, want 200", code)
	}

	// 1. The admin disables the user.
	if w := call(adminAPI, http.MethodPut, userPath, `{"active":false}`); w.Code != http.StatusOK {
		t.Fatalf("PUT active=false: status %d, want 200", w.Code)
	}

	// The credentials issued before the disable are refused: the session
	// no longer validates, and a refresh issues no access token.
	if code := validate(); code != http.StatusUnauthorized {
		t.Fatalf("validate with the pre-disable access cookie: status %d, want 401", code)
	}
	refreshW := call(authAPI, http.MethodPost, "/api/v1/auth/session/refresh", `{"refresh_token":"`+oldRefresh+`"}`)
	var refreshed map[string]any
	_ = json.Unmarshal(refreshW.Body.Bytes(), &refreshed)
	if tok, _ := refreshed["access_token"].(string); tok != "" || refreshW.Code != http.StatusUnauthorized {
		t.Fatalf("refresh with the pre-disable refresh token: status %d, access token issued: %v; want 401 and none", refreshW.Code, tok != "")
	}

	// 2. The admin can still read the disabled user, and sees it disabled.
	w := call(adminAPI, http.MethodGet, userPath, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET disabled user: status %d, want 200 (the admin must see a disabled user)", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET disabled user: parse JSON: %v", err)
	}
	if got["id"] != created.ID.String() || got["banned"] != true {
		t.Fatalf("GET disabled user: want id %s with banned=true, got id=%v banned=%v", created.ID, got["id"], got["banned"])
	}

	// 3. The disabled user is refused at login.
	if code := login(); code != http.StatusUnauthorized {
		t.Fatalf("login while disabled: status %d, want 401", code)
	}

	// 4. The admin enables the user again.
	if w := call(adminAPI, http.MethodPut, userPath, `{"active":true}`); w.Code != http.StatusOK {
		t.Fatalf("PUT active=true: status %d, want 200 (a disabled user must be re-enableable)", w.Code)
	}

	// 5. The re-enabled user signs in again.
	if code := login(); code != http.StatusOK {
		t.Fatalf("login after re-enable: status %d, want 200", code)
	}
}

// adminUsersAPI mounts the users routes behind an org_admin of org, with the
// read and update scopes the routes require.
func adminUsersAPI(orgID uuid.UUID, repos *postgres.Repositories) *gin.Engine {
	admin := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
		Email:          "admin@example.invalid",
		Scope:          strings.Join([]string{domain.ScopeUsersRead, domain.ScopeUsersUpdate}, " "),
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(admin))
	handlers.RegisterUsersRoutes(r, handlers.UsersHandlerDeps{
		UserService: service.NewUserService(nil, repos.User),
		UserRepo:    repos.User,
	})
	return r
}

// A pending self-registration is held as banned=true, role=org_user; approval
// is the only way out. It read its target through the banned-filtering
// lookup too, so it could never find the user it exists to approve.
func TestE2E_OSS_AdminApprovesPendingRegistration(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)
	pending, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          strings.ToLower("e2e-pending-" + uuid.NewString() + "@example.invalid"),
		PasswordHash:   "pd-" + uuid.NewString(),
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		Banned:         true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() { _ = repos.User.Delete(context.Background(), pending.ID, pending.OrganizationID) })

	api := adminUsersAPI(org.ID, repos)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+pending.ID.String()+"/approve", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("approve pending registration: status %d, want 200", w.Code)
	}
	after, err := repos.User.GetByID(ctx, pending.ID)
	if err != nil || after == nil || after.Banned {
		t.Fatalf("approved user: want readable and banned=false, got err=%v banned=%v", err, after != nil && after.Banned)
	}
}

// The admin read sees a disabled user but NOT a deleted one: a soft-deleted
// user stays 404, exactly as before.
func TestE2E_OSS_AdminReadOfDeletedUserStaysNotFound(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)
	gone, err := repos.User.Create(ctx, &domain.User{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          strings.ToLower("e2e-deleted-" + uuid.NewString() + "@example.invalid"),
		PasswordHash:   "dl-" + uuid.NewString(),
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	if err := repos.User.Delete(ctx, gone.ID, gone.OrganizationID); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}

	api := adminUsersAPI(org.ID, repos)
	for _, tc := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPut, `{"active":true}`},
	} {
		req := httptest.NewRequest(tc.method, "/api/v1/users/"+gone.ID.String(), strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s deleted user: status %d, want 404", tc.method, w.Code)
		}
	}
}
