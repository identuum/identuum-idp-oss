//go:build integration

// Package e2e — integration coverage for the OSS MFA-policy gate added
// by slice agent-a-identuum-idp-oss-mfa-policy-enforcement. Pins the
// wire contract operators and identuum-ui depend on:
//
//   - admin login with mfa_enabled=false → 401 mfa_enrollment_required
//     with NO Set-Cookie headers and NO token material in the body;
//   - validate against the same email continues to return 401
//     unauthorized (the failed login could not have produced a session).
//
// Test discipline mirrors login_validate_http_test.go: randomized
// email + plaintext + tenant org per run, t.Cleanup soft-deletes,
// helper classifyLoginBody maps the response body to a short
// non-secret category before assertion.
package e2e

import (
	"context"
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

func TestE2E_OSS_AdminWithoutMFAReturnsEnrollmentRequired(t *testing.T) {
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
		t.Fatal("repository factory returned nil repo")
	}

	// Seed an isolated tenant org (mfa_policy=optional via
	// seedTestOrganization) + an org_admin user with mfa_enabled=false.
	// Even though the org policy is optional, the role-based rule
	// MUST require MFA enrolment.
	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-mfa-policy-" + uuid.NewString() + "@example.invalid")
	plaintext := "mp-" + uuid.NewString() + "-marker-not-printed"

	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed: uuid generation failed: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		// MFAEnabled is the zero value (false) — the row mirrors the
		// post-bootstrap / post-recovery state of site_admin@system.local.
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

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

	loginBody := `{"email":"` + email + `","password":"` + plaintext + `","remember_me":false}`
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Host = "localhost:7113"
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusUnauthorized {
		t.Fatalf("admin without MFA: want 401 mfa_enrollment_required, got status=%d body=%s", loginW.Code, classifyLoginBody(loginW.Body.String()))
	}
	if !strings.Contains(loginW.Body.String(), `"error":"mfa_enrollment_required"`) {
		t.Fatalf("admin without MFA: body shape: %s (want mfa_enrollment_required)", classifyLoginBody(loginW.Body.String()))
	}

	// SECURITY: NO Set-Cookie may be emitted on the enrolment-required
	// path. The handler MUST NOT call setAuthCookies on any
	// emitLoginError branch.
	cookies := loginW.Result().Cookies()
	if len(cookies) != 0 {
		names := make([]string, 0, len(cookies))
		for _, c := range cookies {
			names = append(names, c.Name)
		}
		t.Fatalf("admin without MFA: Set-Cookie present on enrolment-required path: %v", names)
	}

	// Validate must continue to reject the unauthenticated request —
	// no session could have been created.
	validateW := httptest.NewRecorder()
	r.ServeHTTP(validateW, httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil))
	if validateW.Code != http.StatusUnauthorized {
		t.Fatalf("validate after failed admin login: want 401, got %d", validateW.Code)
	}
}
