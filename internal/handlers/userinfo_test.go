package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// userinfoFakeVerifier returns canned IntrospectionClaims (or
// an error) for the userinfo handler tests.
type userinfoFakeVerifier struct {
	claims *service.IntrospectionClaims
	err    error
}

func (f *userinfoFakeVerifier) IntrospectToken(_ context.Context, _ string) (*service.IntrospectionClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

type userinfoFakeRevocationChecker struct {
	revoked map[string]bool
	err     error
}

func (f *userinfoFakeRevocationChecker) IsRevoked(_ context.Context, jti string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[jti], nil
}

func newUserinfoEngine(t *testing.T, verifier service.TokenClaimsVerifier, checker service.TokenRevocationChecker) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	intro := service.NewIntrospectionService(nil, verifier, nil)
	if checker != nil {
		intro.WithRevocationChecker(checker)
	}
	rec := &audit.Recorder{}
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
		IntrospectionService: intro,
		Audit:                rec,
	})
	return r, rec
}

// ---------- Route absence ----------

func TestUserinfo_RouteAbsentWithoutIntrospectionService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------- Missing / invalid bearer ----------

func TestUserinfo_MissingBearerIs401(t *testing.T) {
	r, _ := newUserinfoEngine(t, &userinfoFakeVerifier{claims: &service.IntrospectionClaims{Sub: "x"}}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("WWW-Authenticate not set: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestUserinfo_VerifierErrorIs401(t *testing.T) {
	r, _ := newUserinfoEngine(t, &userinfoFakeVerifier{err: errors.New("invalid token")}, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer BAD-TOKEN-MUST-NOT-LEAK")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "BAD-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
}

func TestUserinfo_RevokedTokenIs401(t *testing.T) {
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: "user-x", UserID: uuid.New(), Email: "x@example.com", Jti: "jti-rev",
	}}
	c := &userinfoFakeRevocationChecker{revoked: map[string]bool{"jti-rev": true}}
	r, _ := newUserinfoEngine(t, v, c)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token returned %d, want 401", w.Code)
	}
}

// ---------- Valid token success ----------

func TestUserinfo_ValidTokenReturnsSub(t *testing.T) {
	uid := uuid.New()
	oid := uuid.New()
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Email: "user@example.com",
		OrgID: oid, Role: "org_user", Jti: "jti-good",
	}}
	r, rec := newUserinfoEngine(t, v, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer GOOD-TOKEN-MUST-NOT-LEAK")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["sub"] != uid.String() {
		t.Errorf("sub = %v", body["sub"])
	}
	if body["email"] != "user@example.com" {
		t.Errorf("email = %v", body["email"])
	}
	if body["organization_id"] != oid.String() {
		t.Errorf("organization_id = %v", body["organization_id"])
	}
	if body["role"] != "org_user" {
		t.Errorf("role = %v", body["role"])
	}
	for _, banned := range []string{"jti", "session_id", "access_token", "token", "client_secret"} {
		if _, ok := body[banned]; ok {
			t.Errorf("response leaked banned key %q", banned)
		}
	}
	if strings.Contains(w.Body.String(), "GOOD-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token")
	}
	// jti must NOT appear anywhere in the body even though it
	// drove the revocation check.
	if strings.Contains(w.Body.String(), "jti-good") {
		t.Errorf("response leaked jti: %q", w.Body.String())
	}
	// Audit fires with safe sub_kind only.
	var fired bool
	for _, e := range rec.Events() {
		if e.Action == "oidc_userinfo.served" {
			fired = true
			if e.Metadata["sub_kind"] != "user" {
				t.Errorf("sub_kind = %v", e.Metadata["sub_kind"])
			}
			for k := range e.Metadata {
				if k == "sub" || k == "token" || k == "jti" || k == "client_secret" {
					t.Errorf("audit metadata leaked banned key %q", k)
				}
			}
		}
	}
	if !fired {
		t.Errorf("audit oidc_userinfo.served not emitted")
	}
}

func TestUserinfo_ClientCredentialsTokenReturnsClientSub(t *testing.T) {
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-cc",
	}}
	r, _ := newUserinfoEngine(t, v, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["sub"] != "cli-1" {
		t.Errorf("sub = %v", body["sub"])
	}
	if _, ok := body["email"]; ok {
		t.Errorf("email leaked for client_credentials token: %v", body["email"])
	}
}

// ---------- service-account token ----------

func TestUserinfo_ServiceAccountOmitsEmail(t *testing.T) {
	saID := uuid.New()
	orgID := uuid.New()
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub:       saID.String(),
		ClientID:  "cli-1",
		Email:     "leaked@example.com",
		OrgID:     orgID,
		Role:      "org_admin",
		ActorType: service.ActorTypeServiceAccount,
	}}
	r, rec := newUserinfoEngine(t, v, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["sub"] != saID.String() {
		t.Errorf("sub = %v", body["sub"])
	}
	if got, ok := body["email"].(string); ok && got != "" {
		t.Errorf("service-account token leaked email: %q", got)
	}
	if body["organization_id"] != orgID.String() {
		t.Errorf("org id = %v", body["organization_id"])
	}
	if body["role"] != "org_admin" {
		t.Errorf("role = %v", body["role"])
	}
	// Audit sub_kind must be service_account.
	var fired bool
	for _, e := range rec.Events() {
		if e.Action == "oidc_userinfo.served" {
			fired = true
			if e.Metadata["sub_kind"] != service.ActorTypeServiceAccount {
				t.Errorf("audit sub_kind = %v, want %s", e.Metadata["sub_kind"], service.ActorTypeServiceAccount)
			}
		}
	}
	if !fired {
		t.Errorf("audit oidc_userinfo.served not fired")
	}
}

// ---------- profile claims (name) ----------

// fakeUserinfoUserLookup answers GetByID with one canned user.
type fakeUserinfoUserLookup struct {
	user *domain.User
	err  error
}

func (f *fakeUserinfoUserLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	return f.user, f.err
}

func userinfoStrPtr(s string) *string { return &s }

// THE-PKCE-DECISION (conformance-measured gap): a human subject gets `name`
// from the user record when a UserLookup is wired; a service-account token
// NEVER gets one (no display name to expose); a lookup failure degrades to
// the claim being absent, never a 500.
func TestUserinfo_NameFromUserRecord(t *testing.T) {
	uid := uuid.New()
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Email: "user@example.com",
	}}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	intro := service.NewIntrospectionService(nil, v, nil)
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
		IntrospectionService: intro,
		UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: uid, Name: userinfoStrPtr("Alice Example")}},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["name"] != "Alice Example" {
		t.Errorf("name = %v, want the user record's display name", body["name"])
	}
}

// RULE: USERINFO-HUMAN-NAME-1
func TestUserinfo_ServiceAccountNeverGetsName(t *testing.T) {
	saID := uuid.New()
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: saID.String(), UserID: saID, ClientID: "cli-1",
		ActorType: service.ActorTypeServiceAccount,
	}}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	intro := service.NewIntrospectionService(nil, v, nil)
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
		IntrospectionService: intro,
		UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: saID, Name: userinfoStrPtr("MUST-NOT-APPEAR")}},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "MUST-NOT-APPEAR") {
		t.Errorf("service-account token got a name claim: %q", w.Body.String())
	}
}

func TestUserinfo_NameLookupFailureDegradesToAbsent(t *testing.T) {
	uid := uuid.New()
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid,
	}}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	intro := service.NewIntrospectionService(nil, v, nil)
	RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
		IntrospectionService: intro,
		UserLookup:           &fakeUserinfoUserLookup{err: errors.New("db down")},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer ANY")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (claim degrades, never a 500)", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if _, ok := body["name"]; ok {
		t.Errorf("name present despite lookup failure: %v", body["name"])
	}
}

// ---------- POST form-encoded access_token ----------

func TestUserinfo_POSTWithFormAccessToken(t *testing.T) {
	v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{Sub: "sub-1"}}
	r, _ := newUserinfoEngine(t, v, nil)
	body := strings.NewReader("access_token=ANY")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oidc/userinfo", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}
