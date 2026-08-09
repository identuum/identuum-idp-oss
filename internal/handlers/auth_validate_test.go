package handlers

// Unit tests for HandleValidateSession (GET /api/v1/validate) and the
// login response's new Role field.
//
// Test discipline:
//   - The "JWT" passed to the stub verifier is a sentinel placeholder
//     string — never a real token — and the verifier returns a
//     hand-built *domain.Principal so the test exercises the handler's
//     control flow without needing a real JWKS round-trip.
//   - The test never prints the token, cookie value, or any returned
//     credential into a failure message.
//   - The handler is registered exactly as production wires it (via
//     RegisterAuthSessionRoutes) so the route-registration guard is
//     covered too.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// stubTokenVerifier satisfies ValidateTokenVerifier without touching
// the JWT signing path. The handler treats VerifyBearerToken's success
// + error as opaque, so a hand-built *domain.Principal is sufficient
// coverage. A non-nil err always overrides the principal.
type stubTokenVerifier struct {
	allow     string // exact bearer-token value that succeeds
	principal *domain.Principal
	err       error
}

func (s *stubTokenVerifier) VerifyBearerToken(_ context.Context, token string) (*domain.Principal, error) {
	if s.err != nil {
		return nil, s.err
	}
	if token != s.allow {
		return nil, errors.New("stub: token mismatch")
	}
	return s.principal, nil
}

// stubSessionLookup + stubUserByIDLookup mirror the in-memory fakes the
// existing handler tests use but are scoped to the /validate path so the
// new tests do not interact with the older auth_sessions_test.go fakes.
type stubSessionLookup struct {
	byID map[uuid.UUID]*domain.Session
}

func (s *stubSessionLookup) GetByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	if v, ok := s.byID[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, nil
}

type stubUserByIDLookupForValidate struct {
	byID map[uuid.UUID]*domain.User
}

func (s *stubUserByIDLookupForValidate) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if v, ok := s.byID[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, nil
}

// newValidateEngine spins up a Gin router with ONLY the validate-route
// deps wired — no LocalLogin, no UserSession. This proves the route
// registers (and only registers) on the three-dep gate.
func newValidateEngine(t *testing.T, verifier *stubTokenVerifier, sessions *stubSessionLookup, users *stubUserByIDLookupForValidate) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		TokenVerifier: verifier,
		SessionLookup: sessions,
		UserLookup:    users,
	})
	return r
}

// seedValidPrincipal builds a matched (principal, session, user) trio
// that represents a freshly-logged-in site_admin. The bearer-token
// value is a sentinel placeholder.
const validSentinelToken = "validate-test-sentinel-token-not-a-real-jwt"

func seedValidatePrincipal(t *testing.T, role domain.UserRole) (*stubTokenVerifier, *stubSessionLookup, *stubUserByIDLookupForValidate, uuid.UUID, uuid.UUID) {
	t.Helper()
	userID := uuid.New()
	sessionID := uuid.New()
	orgID := uuid.New()
	now := time.Now()
	user := &domain.User{
		ID:             userID,
		OrganizationID: orgID,
		Email:          "alice@example.invalid",
		Role:           role,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	}
	session := &domain.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: now.Add(time.Hour),
		IsValid:   true,
	}
	return &stubTokenVerifier{
			allow: validSentinelToken,
			principal: &domain.Principal{
				UserID:    userID,
				SessionID: sessionID,
			},
		},
		&stubSessionLookup{byID: map[uuid.UUID]*domain.Session{sessionID: session}},
		&stubUserByIDLookupForValidate{byID: map[uuid.UUID]*domain.User{userID: user}},
		userID,
		sessionID
}

// --- Route-registration gate ---------------------------------------------

func TestValidateRoute_AbsentWithoutAllThreeDeps(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// No deps at all → route absent.
	r := gin.New()
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no-deps validate: want 404, got %d", w.Code)
	}

	// Only verifier wired → still absent (no session/user lookup means
	// we cannot complete the chain — fail closed at registration time).
	r = gin.New()
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		TokenVerifier: &stubTokenVerifier{},
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("partial-deps validate: want 404, got %d", w.Code)
	}
}

// --- Happy path: cookie or Authorization header --------------------------

func TestValidateRoute_AcceptsAccessTokenCookie(t *testing.T) {
	verifier, sessions, users, userID, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	r := newValidateEngine(t, verifier, sessions, users)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	if body["success"] != true {
		t.Fatalf("success: want true, got %v", body["success"])
	}
	if body["role"] != "site_admin" {
		t.Fatalf("top-level role: want site_admin, got %v", body["role"])
	}
	user, _ := body["user"].(map[string]any)
	if user == nil {
		t.Fatal("user object missing")
	}
	if user["role"] != "site_admin" {
		t.Fatalf("user.role: want site_admin, got %v", user["role"])
	}
	if user["id"] != userID.String() {
		t.Fatalf("user.id: want %s, got %v", userID, user["id"])
	}
	if user["email"] != "alice@example.invalid" {
		t.Fatalf("user.email: want alice@example.invalid, got %v", user["email"])
	}
	if user["active"] != true {
		t.Fatalf("user.active: want true, got %v", user["active"])
	}
	if user["deleted"] != false {
		t.Fatalf("user.deleted: want false, got %v", user["deleted"])
	}
}

func TestValidateRoute_AcceptsAuthorizationBearer(t *testing.T) {
	verifier, sessions, users, _, _ := seedValidatePrincipal(t, domain.RoleOrgAdmin)
	r := newValidateEngine(t, verifier, sessions, users)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.Header.Set("Authorization", "Bearer "+validSentinelToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != "org_admin" {
		t.Fatalf("role: want org_admin, got %v", body["role"])
	}
}

func TestValidateRoute_CookieTakesPrecedenceOverHeader(t *testing.T) {
	// The cookie carries the valid sentinel; the header carries a
	// bogus value. Cookie-first ordering means the request succeeds.
	verifier, sessions, users, _, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	r := newValidateEngine(t, verifier, sessions, users)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
}

// --- Negative paths ------------------------------------------------------

func TestValidateRoute_MissingTokenIs401(t *testing.T) {
	verifier, sessions, users, _, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	r := newValidateEngine(t, verifier, sessions, users)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("body = %q", w.Body.String())
	}
}

func TestValidateRoute_InvalidTokenIs401(t *testing.T) {
	verifier, sessions, users, _, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "wrong-token-not-the-sentinel"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_RevokedSessionIs401(t *testing.T) {
	verifier, sessions, users, _, sessionID := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	// Mark the session as revoked.
	now := time.Now()
	reason := "test-revoked"
	sessions.byID[sessionID].RevokedAt = &now
	sessions.byID[sessionID].RevokedReason = &reason
	sessions.byID[sessionID].IsValid = false

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked-session: status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_ExpiredSessionIs401(t *testing.T) {
	verifier, sessions, users, _, sessionID := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	sessions.byID[sessionID].ExpiresAt = time.Now().Add(-time.Hour)

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired-session: status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_MissingSessionIs401(t *testing.T) {
	verifier, sessions, users, _, sessionID := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	delete(sessions.byID, sessionID)

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing-session: status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_BannedUserIs401(t *testing.T) {
	verifier, sessions, users, userID, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	users.byID[userID].Banned = true

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("banned-user: status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_DeletedUserIs401(t *testing.T) {
	verifier, sessions, users, userID, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	deletedAt := time.Now()
	users.byID[userID].DeletedAt = &deletedAt

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("deleted-user: status = %d, want 401", w.Code)
	}
}

func TestValidateRoute_PrincipalWithoutSessionIDIs401(t *testing.T) {
	verifier, sessions, users, userID, _ := seedValidatePrincipal(t, domain.RoleSiteAdmin)
	verifier.principal = &domain.Principal{UserID: userID} // SessionID = uuid.Nil

	r := newValidateEngine(t, verifier, sessions, users)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validSentinelToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when SessionID is Nil", w.Code)
	}
}

// --- Login response Role field ------------------------------------------

// TestLoginRoute_ResponseIncludesRole pins the role field on a
// successful login response. It deliberately uses an org_user role
// (not site_admin / org_admin) so the post-this-slice MFA policy gate
// does not divert the response to the mfa_enrollment_required path.
// Admin-role + MFA-not-enrolled coverage lives in
// auth_mfa_policy_test.go::TestLoginRoute_SiteAdminWithoutMFAReturnsEnrollmentRequiredAndNoCookies
// and its siblings.
func TestLoginRoute_ResponseIncludesRole(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["user@example.invalid"] = []*domain.User{{
			ID: uuid.New(), Email: "user@example.invalid",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			Role:          domain.RoleOrgUser,
		}}
	})
	body := strings.NewReader(`{"email":"user@example.invalid","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["role"] != "org_user" {
		t.Fatalf("login response role: want org_user, got %v", resp["role"])
	}
	if resp["email"] != "user@example.invalid" {
		t.Fatalf("login response email: want user@example.invalid, got %v", resp["email"])
	}
}
