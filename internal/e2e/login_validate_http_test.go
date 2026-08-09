//go:build integration

// Package e2e — integration coverage for the full login → cookie →
// /validate round-trip exposed by RegisterAuthSessionRoutes. This is
// the contract identuum-ui's getServerSession() helper consumes after
// the local-demo browser login.
//
// The test composes the real Gin router with the real PgxUserRepository
// + UserSessionService + UserTokenService + RepositoryVerifier, against
// the live compose Postgres on 127.0.0.1:5513. It pins:
//
//  1. POST /api/v1/auth/login returns 200 with `role` populated.
//  2. The response also returns Set-Cookie for access_token (and
//     refresh_token), HttpOnly, SameSite=Lax, Path=/.
//  3. GET /api/v1/validate with the access_token cookie returns 200
//     with the same role + user info.
//  4. GET /api/v1/validate without a cookie returns 401.
//
// Test discipline:
//   - Randomized email + plaintext + tenant org per run so the test is
//     isolated from the operator's demo data.
//   - Cookie values, access tokens, and refresh tokens are NEVER
//     printed in failure messages. Only structural assertions are made
//     (cookie presence, attribute presence, MaxAge bound, status code,
//     JSON field values).
//   - t.Cleanup soft-deletes the seeded user + org.
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
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_LoginCookiesAndValidate_RoundTrip(t *testing.T) {
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
	if repos == nil || repos.User == nil || repos.Session == nil || repos.Key == nil {
		t.Fatal("repository factory returned nil User, Session, or Key repo")
	}

	// Seed an isolated tenant org (mfa_policy=optional via
	// seedTestOrganization) + an org_user with a known plaintext
	// password. The role is org_user so the post-MFA-policy-enforcement
	// gate does NOT divert the response to mfa_enrollment_required —
	// admin coverage for that path lives in
	// TestE2E_OSS_AdminWithoutMFAReturnsEnrollmentRequired below.
	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-login-validate-" + uuid.NewString() + "@example.invalid")
	plaintext := "lv-" + uuid.NewString() + "-marker-not-printed"

	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
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

	// Ensure at least one active signing key exists — the
	// UserTokenService cannot mint a JWT otherwise. If the demo DB
	// already has the bootstrap-emitted EdDSA key from the prior
	// bootstrap slice, this is a no-op; if it does not, we generate
	// one inline. The KID is read back to assert structurally only —
	// the private-key material never leaves the service.
	keySvc := service.NewKeyService(repos.Key)
	active, err := keySvc.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive keys: %v", err)
	}
	if len(active) == 0 {
		_, err := keySvc.Generate(ctx, service.GenerateKeyOptions{
			Algorithm: string(domain.KeyAlgorithmEdDSA),
			State:     domain.KeyStateActive,
		})
		if err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}

	const issuer = "http://localhost:7113"

	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	login := service.NewLocalLoginService(nil, repos.User, sessions, nil)
	userToken := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: issuer})
	verifier := auth.NewRepositoryVerifier(nil, repos.Key, auth.VerifierOptions{ExpectedIssuer: issuer})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	handlers.RegisterAuthSessionRoutes(r, handlers.AuthSessionsHandlerDeps{
		LocalLogin:    login,
		UserSession:   sessions,
		UserToken:     userToken,
		UserLookup:    repos.User,
		SessionLookup: repos.Session,
		TokenVerifier: verifier,
	})

	// ---------- POST /api/v1/auth/login ----------

	loginBody := `{"email":"` + email + `","password":"` + plaintext + `","remember_me":false}`
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Host = "localhost:7113" // matches the localhost-Secure branch
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusOK {
		// loginW.Body MAY contain a JSON body with no secrets;
		// however to be safe we map common bodies to a category
		// string rather than echoing the response.
		t.Fatalf("login: status = %d (want 200); body shape: %s", loginW.Code, classifyLoginBody(loginW.Body.String()))
	}

	var loginResp map[string]any
	if err := json.Unmarshal(loginW.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("login: parse JSON failed: %v", err)
	}
	if loginResp["role"] != "org_user" {
		t.Fatalf("login: role: want org_user, got %v", loginResp["role"])
	}
	if loginResp["email"] != email {
		t.Fatalf("login: email mismatch")
	}
	if loginResp["user_id"] != seededID.String() {
		t.Fatalf("login: user_id mismatch")
	}
	// Token presence is structural — value is never compared.
	if accessTok, _ := loginResp["access_token"].(string); accessTok == "" {
		t.Fatal("login: access_token missing from response body (UserTokenService should have minted one)")
	}
	if refreshTok, _ := loginResp["refresh_token"].(string); refreshTok == "" {
		t.Fatal("login: refresh_token missing from response body")
	}

	cookies := loginW.Result().Cookies()
	accessCookie := findCookieByName(cookies, "access_token")
	if accessCookie == nil {
		t.Fatal("login: Set-Cookie access_token missing")
	}
	if !accessCookie.HttpOnly {
		t.Fatal("login: access_token cookie must be HttpOnly")
	}
	if accessCookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("login: access_token cookie must be SameSite=Lax")
	}
	if accessCookie.Path != "/" {
		t.Fatal("login: access_token cookie must have Path=/")
	}
	if accessCookie.MaxAge <= 0 || accessCookie.MaxAge > 3600 {
		t.Fatalf("login: access_token MaxAge out of expected bound (got %d, want 0<x<=3600)", accessCookie.MaxAge)
	}
	if accessCookie.Value == "" {
		t.Fatal("login: access_token cookie value empty")
	}

	refreshCookie := findCookieByName(cookies, "refresh_token")
	if refreshCookie == nil {
		t.Fatal("login: Set-Cookie refresh_token missing (UserSessionService should have issued one)")
	}
	if !refreshCookie.HttpOnly {
		t.Fatal("login: refresh_token cookie must be HttpOnly")
	}
	// remember_me=false → MaxAge=0 (session cookie) is the contract.
	if refreshCookie.MaxAge != 0 {
		t.Fatalf("login: refresh_token MaxAge (remember_me=false): want 0, got %d", refreshCookie.MaxAge)
	}

	// ---------- GET /api/v1/validate (cookie path) ----------

	validateReq := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	validateReq.AddCookie(&http.Cookie{Name: "access_token", Value: accessCookie.Value})
	validateW := httptest.NewRecorder()
	r.ServeHTTP(validateW, validateReq)

	if validateW.Code != http.StatusOK {
		t.Fatalf("validate (cookie): status = %d (want 200); body shape: %s", validateW.Code, classifyValidateBody(validateW.Body.String()))
	}
	var validateResp map[string]any
	if err := json.Unmarshal(validateW.Body.Bytes(), &validateResp); err != nil {
		t.Fatalf("validate: parse JSON failed: %v", err)
	}
	if validateResp["success"] != true {
		t.Fatalf("validate: success: want true, got %v", validateResp["success"])
	}
	if validateResp["role"] != "org_user" {
		t.Fatalf("validate: top-level role: want org_user, got %v", validateResp["role"])
	}
	user, _ := validateResp["user"].(map[string]any)
	if user == nil {
		t.Fatal("validate: user object missing")
	}
	if user["role"] != "org_user" {
		t.Fatalf("validate: user.role: want org_user, got %v", user["role"])
	}
	if user["id"] != seededID.String() {
		t.Fatal("validate: user.id mismatch")
	}
	if user["email"] != email {
		t.Fatal("validate: user.email mismatch")
	}
	if user["organization_id"] != org.ID.String() {
		t.Fatal("validate: user.organization_id mismatch")
	}

	// ---------- GET /api/v1/validate (Authorization: Bearer path) ----------

	validateBearerReq := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	validateBearerReq.Header.Set("Authorization", "Bearer "+accessCookie.Value)
	validateBearerW := httptest.NewRecorder()
	r.ServeHTTP(validateBearerW, validateBearerReq)
	if validateBearerW.Code != http.StatusOK {
		t.Fatalf("validate (bearer): status = %d (want 200)", validateBearerW.Code)
	}

	// ---------- GET /api/v1/validate (no token) ----------

	validateNoTokenW := httptest.NewRecorder()
	r.ServeHTTP(validateNoTokenW, httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil))
	if validateNoTokenW.Code != http.StatusUnauthorized {
		t.Fatalf("validate (no token): status = %d, want 401", validateNoTokenW.Code)
	}
}

// findCookieByName is a local helper (the handlers-package findCookie
// is unexported). Defined here to avoid leaking exported test surface
// out of the handlers package.
func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// classifyLoginBody maps a login-response body string to a short
// non-secret category so failure assertions never echo a refresh
// token or access token. Returned strings are safe to log.
func classifyLoginBody(b string) string {
	switch {
	case strings.Contains(b, `"error":"invalid_credentials"`):
		return "invalid_credentials"
	case strings.Contains(b, `"error":"mfa_required"`):
		return "mfa_required"
	case strings.Contains(b, `"error":"account_unverified"`):
		return "account_unverified"
	case strings.Contains(b, `"refresh_token"`):
		return "success-shape"
	default:
		return "unknown-shape"
	}
}

// classifyValidateBody is the same idea for the /validate endpoint.
func classifyValidateBody(b string) string {
	switch {
	case strings.Contains(b, `"error":"unauthorized"`):
		return "unauthorized"
	case strings.Contains(b, `"success":true`):
		return "success"
	default:
		return "unknown-shape"
	}
}
