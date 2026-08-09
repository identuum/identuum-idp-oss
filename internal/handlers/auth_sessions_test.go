package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// userTokenKeyProvider returns an in-memory SigningKeyProvider
// seeded with one EdDSA key — just enough for the
// access-token-mint tests.
type handlerKeyProvider struct {
	keys []domain.SigningKey
}

func (p *handlerKeyProvider) ListActive(context.Context) ([]domain.SigningKey, error) {
	return p.keys, nil
}

func userTokenKeyProvider(t *testing.T) service.SigningKeyProvider {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM, _ := x509.MarshalPKCS8PrivateKey(priv)
	return &handlerKeyProvider{
		keys: []domain.SigningKey{
			{
				KID:        "kid-eddsa",
				Algorithm:  domain.KeyAlgorithmEdDSA,
				PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkPEM})),
				State:      domain.KeyStateActive,
			},
		},
	}
}

// inMemoryUserLookupForHandlers mirrors the service-test fake but
// lives in the handlers package.
type inMemoryUserLookupForHandlers struct {
	byEmail map[string][]*domain.User
}

func (r *inMemoryUserLookupForHandlers) FindUsersByEmail(_ context.Context, email string) ([]*domain.User, error) {
	out, ok := r.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, nil
	}
	return out, nil
}

// inMemorySessionRepoForHandlers is the smallest SessionRepository
// the handler tests need. Only Create / GetByTokenSelector /
// Update / Revoke / DeleteExpiredReturning are exercised.
type inMemorySessionRepoForHandlers struct {
	byID       map[uuid.UUID]*domain.Session
	bySelector map[uuid.UUID]*domain.Session
}

func newSessionRepoForHandlers() *inMemorySessionRepoForHandlers {
	return &inMemorySessionRepoForHandlers{
		byID:       map[uuid.UUID]*domain.Session{},
		bySelector: map[uuid.UUID]*domain.Session{},
	}
}
func (r *inMemorySessionRepoForHandlers) Create(_ context.Context, s *domain.Session) (*domain.Session, error) {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return &cp, nil
}
func (r *inMemorySessionRepoForHandlers) GetByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	s, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}
func (r *inMemorySessionRepoForHandlers) GetByTokenSelector(_ context.Context, sel uuid.UUID) (*domain.Session, error) {
	s, ok := r.bySelector[sel]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}
func (r *inMemorySessionRepoForHandlers) Update(_ context.Context, s *domain.Session, _ uuid.UUID) error {
	old, ok := r.byID[s.ID]
	if !ok {
		return errors.New("not found")
	}
	if old.TokenSelector != nil {
		delete(r.bySelector, *old.TokenSelector)
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return nil
}
func (r *inMemorySessionRepoForHandlers) RotateToken(_ context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	s, ok := r.byID[sessionID]
	if !ok {
		return nil, false, nil
	}
	if s.TokenValidatorHash == nil || *s.TokenValidatorHash != expectedValidatorHash || !s.IsValid || s.RevokedAt != nil {
		return nil, false, nil
	}
	s.TokenValidatorHash = &newValidatorHash
	s.ExpiresAt = newExpiresAt
	s.LastUsedAt = &lastUsedAt
	cp := *s
	return &cp, true, nil
}
func (r *inMemorySessionRepoForHandlers) RecordACRUplift(context.Context, uuid.UUID, time.Time, string) error {
	return nil
}
func (r *inMemorySessionRepoForHandlers) Revoke(_ context.Context, id, _ uuid.UUID, reason string) error {
	s, ok := r.byID[id]
	if !ok {
		return nil
	}
	now := time.Now()
	s.RevokedAt = &now
	s.RevokedReason = &reason
	s.IsValid = false
	return nil
}
func (r *inMemorySessionRepoForHandlers) RevokeByUserID(_ context.Context, userID uuid.UUID, reason string) error {
	now := time.Now()
	for _, s := range r.byID {
		if s.UserID == userID {
			s.RevokedAt = &now
			s.RevokedReason = &reason
			s.IsValid = false
		}
	}
	return nil
}
func (r *inMemorySessionRepoForHandlers) RevokeByOrganizationID(context.Context, uuid.UUID, string) error {
	return nil
}
func (r *inMemorySessionRepoForHandlers) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (r *inMemorySessionRepoForHandlers) ListByUserID(_ context.Context, userID uuid.UUID, includeInvalid bool) ([]*domain.Session, error) {
	out := make([]*domain.Session, 0)
	for _, s := range r.byID {
		if s.UserID != userID {
			continue
		}
		if !includeInvalid && (!s.IsValid || s.RevokedAt != nil) {
			continue
		}
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}
func (r *inMemorySessionRepoForHandlers) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	return r.ListByUserID(ctx, userID, false)
}
func (r *inMemorySessionRepoForHandlers) CountActiveByUserID(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (r *inMemorySessionRepoForHandlers) DeleteExpiredReturning(context.Context, time.Duration, int) ([]*domain.Session, error) {
	return nil, nil
}
func (r *inMemorySessionRepoForHandlers) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return nil, nil
}
func (r *inMemorySessionRepoForHandlers) GetStats(context.Context) (map[string]int, error) {
	return nil, nil
}

// compile-time check.
var _ repository.SessionRepository = (*inMemorySessionRepoForHandlers)(nil)

func newAuthEngine(t *testing.T, seed func(*inMemoryUserLookupForHandlers)) (*gin.Engine, *service.UserSessionService, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	if seed != nil {
		seed(users)
	}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, users, sessions, mfa)
	rec := &audit.Recorder{}
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		LocalLogin:  login,
		UserSession: sessions,
		Audit:       rec,
	})
	return r, sessions, rec
}

func hashPasswordForHandlers(t *testing.T, p string) string {
	t.Helper()
	h, err := crypto.GenerateHash([]byte(p))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

// ---------- Route absence ----------

func TestAuthRoutes_AbsentWithoutServices(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`)))
	if w.Code != http.StatusNotFound {
		t.Errorf("login route = %d, want 404", w.Code)
	}
}

// ---------- Login ----------

func TestLoginRoute_HappyPathReturnsOneTimeRefreshToken(t *testing.T) {
	r, _, rec := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		uid := uuid.New()
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uid, Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
		}}
	})
	body := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Errorf("refresh_token missing from login response")
	}
	// Audit metadata must NOT leak password / refresh token.
	for _, e := range rec.Events() {
		if e.Action == "user_session.login.success" {
			for k, v := range e.Metadata {
				if k == "password" || k == "refresh_token" || k == "totp_code" {
					t.Errorf("audit leaked banned key %q = %v", k, v)
				}
			}
		}
	}
	if strings.Contains(w.Body.String(), `"password"`) {
		t.Errorf("login response echoed password field")
	}
}

func TestLoginRoute_WrongPasswordIs401InvalidCredentials(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
		}}
	})
	body := strings.NewReader(`{"email":"alice@example.com","password":"wrong"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_credentials"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestLoginRoute_MissingMFAIs401MFARequired(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		secret := "JBSWY3DPEHPK3PXP" // arbitrary base32
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
			MFAEnabled:    true,
			MFASecret:     &secret,
		}}
	})
	body := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"mfa_required"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

// ---------- Refresh ----------

func TestRefreshRoute_RotatesAndOldTokenCannotBeReused(t *testing.T) {
	r, _, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
		}}
	})
	loginBody := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	var loginResp map[string]any
	_ = json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	firstToken := loginResp["refresh_token"].(string)

	refreshBody := strings.NewReader(`{"refresh_token":"` + firstToken + `"}`)
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", refreshBody)
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshW := httptest.NewRecorder()
	r.ServeHTTP(refreshW, refreshReq)
	if refreshW.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body=%q", refreshW.Code, refreshW.Body.String())
	}
	var refreshResp map[string]any
	_ = json.Unmarshal(refreshW.Body.Bytes(), &refreshResp)
	secondToken := refreshResp["refresh_token"].(string)
	if secondToken == firstToken {
		t.Errorf("rotation did not change token")
	}
	// Old token must no longer be valid.
	reuseBody := strings.NewReader(`{"refresh_token":"` + firstToken + `"}`)
	reuseReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", reuseBody)
	reuseReq.Header.Set("Content-Type", "application/json")
	reuseW := httptest.NewRecorder()
	r.ServeHTTP(reuseW, reuseReq)
	if reuseW.Code != http.StatusUnauthorized {
		t.Errorf("reuse status = %d, want 401", reuseW.Code)
	}
}

// ---------- Logout ----------

func TestLogoutRoute_RevokesSession(t *testing.T) {
	r, sessions, _ := newAuthEngine(t, func(u *inMemoryUserLookupForHandlers) {
		u.byEmail["alice@example.com"] = []*domain.User{{
			ID: uuid.New(), Email: "alice@example.com",
			PasswordHash:  hashPasswordForHandlers(t, "correct"),
			EmailVerified: true,
		}}
	})
	_ = sessions // touch to avoid unused
	loginBody := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	var loginResp map[string]any
	_ = json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	token := loginResp["refresh_token"].(string)
	logoutBody := strings.NewReader(`{"refresh_token":"` + token + `"}`)
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", logoutBody)
	logoutReq.Header.Set("Content-Type", "application/json")
	logoutW := httptest.NewRecorder()
	r.ServeHTTP(logoutW, logoutReq)
	if logoutW.Code != http.StatusNoContent {
		t.Errorf("logout status = %d", logoutW.Code)
	}
}

// ---------- Access-token integration ----------

// inMemoryUserLookupForLogin satisfies UserByIDLookup so the
// refresh handler's user-by-ID resolution path can exercise the
// access-token mint.
type inMemoryUserByIDLookup struct {
	byID map[uuid.UUID]*domain.User
}

func (r *inMemoryUserByIDLookup) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if u, ok := r.byID[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, nil
}

// newAuthEngineWithToken wires in a UserTokenService so login +
// refresh return access tokens.
func newAuthEngineWithToken(t *testing.T, seed func(*inMemoryUserLookupForHandlers, *inMemoryUserByIDLookup)) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	users := &inMemoryUserLookupForHandlers{byEmail: map[string][]*domain.User{}}
	byID := &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{}}
	if seed != nil {
		seed(users, byID)
	}
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, users, sessions, mfa)
	// Build a UserTokenService backed by an in-memory EdDSA key.
	keyProvider := userTokenKeyProvider(t)
	userToken := service.NewUserTokenService(nil, keyProvider, service.UserTokenServiceOptions{
		Issuer:         "https://idp.test",
		AccessTokenTTL: time.Hour,
	})
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{
		LocalLogin:  login,
		UserSession: sessions,
		UserToken:   userToken,
		UserLookup:  byID,
		Audit:       &audit.Recorder{},
	})
	return r
}

func TestLoginRoute_WithUserTokenReturnsAccessToken(t *testing.T) {
	r := newAuthEngineWithToken(t, func(u *inMemoryUserLookupForHandlers, byID *inMemoryUserByIDLookup) {
		uid := uuid.New()
		user := &domain.User{
			ID: uid, Email: "alice@example.com",
			PasswordHash:   hashPasswordForHandlers(t, "correct"),
			EmailVerified:  true,
			OrganizationID: uuid.New(),
			Role:           domain.RoleOrgUser,
		}
		u.byEmail["alice@example.com"] = []*domain.User{user}
		byID.byID[uid] = user
	})
	body := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Errorf("access_token missing from login response")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
	if resp["expires_in"] == nil {
		t.Errorf("expires_in missing")
	}
	// Cross-check: response also includes the session refresh
	// token.
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Errorf("refresh_token missing")
	}
}

func TestRefreshRoute_WithUserTokenReturnsAccessToken(t *testing.T) {
	r := newAuthEngineWithToken(t, func(u *inMemoryUserLookupForHandlers, byID *inMemoryUserByIDLookup) {
		uid := uuid.New()
		user := &domain.User{
			ID: uid, Email: "alice@example.com",
			PasswordHash:   hashPasswordForHandlers(t, "correct"),
			EmailVerified:  true,
			OrganizationID: uuid.New(),
			Role:           domain.RoleOrgUser,
		}
		u.byEmail["alice@example.com"] = []*domain.User{user}
		byID.byID[uid] = user
	})
	// Login first.
	loginBody := strings.NewReader(`{"email":"alice@example.com","password":"correct"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	var loginResp map[string]any
	_ = json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	firstRefresh := loginResp["refresh_token"].(string)
	// Refresh.
	refreshBody := strings.NewReader(`{"refresh_token":"` + firstRefresh + `"}`)
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", refreshBody)
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshW := httptest.NewRecorder()
	r.ServeHTTP(refreshW, refreshReq)
	if refreshW.Code != http.StatusOK {
		t.Fatalf("refresh status = %d", refreshW.Code)
	}
	var refreshResp map[string]any
	_ = json.Unmarshal(refreshW.Body.Bytes(), &refreshResp)
	if refreshResp["access_token"] == nil || refreshResp["access_token"] == "" {
		t.Errorf("access_token missing from refresh response")
	}
	if refreshResp["refresh_token"] == nil || refreshResp["refresh_token"] == "" {
		t.Errorf("refresh_token missing from refresh response")
	}
}

func TestLogoutRoute_UnknownTokenSilent204(t *testing.T) {
	r, _, _ := newAuthEngine(t, nil)
	body := strings.NewReader(`{"refresh_token":"` + uuid.NewString() + `.AAAA"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d", w.Code)
	}
}
