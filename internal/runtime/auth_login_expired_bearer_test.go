package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/api"
	"github.com/identuum/identuum-idp-oss/internal/auth"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A client still holding a genuinely signed but EXPIRED access token signs in
// again with fresh credentials: the bearer middleware lets the sign-in routes
// through with no principal, and the credentials in the body decide. The
// stale token never decides anything, and routes outside sign-in still refuse
// it with token_invalid.

type pendingRowRepo struct {
	repository.MFAPendingLoginSessionRepository
	row *domain.MFAPendingLoginSession
}

func (s pendingRowRepo) GetByID(context.Context, uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	cp := *s.row
	return &cp, nil
}

func expiredBearerEngine(t *testing.T, user *domain.User, pending *domain.MFAPendingLoginSession) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(priv.Public())
	keys := &expiredBearerKeyRepo{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		State:     domain.KeyStateActive,
	}}}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"sub": user.ID.String(),
		"sid": uuid.New().String(),
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid-eddsa"
	expired, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	users := &expiredBearerUserRepo{user: user}
	sessions := service.NewUserSessionService(nil, &expiredBearerSessionRepo{}, service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	// These cases refuse the pending handle before consulting any TOTP step.
	// Unexpected repository calls fail the test through the nil embedding.
	replay := service.NewTOTPReplayGuard(nil, &expiredBearerTOTPSteps{}, service.TOTPReplayGuardOptions{})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{Replay: replay})
	enroll := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: pendingRowRepo{row: pending}, Users: users, Issuer: "Identuum", Replay: replay,
	}, service.MFAEnrollmentServiceOptions{})

	// Exercise the real verifier and auth handlers through the composition
	// layer that is permitted to wire them together.
	r := api.NewOSSEngine(api.OSSRouterDeps{
		TokenVerifier:      auth.NewRepositoryVerifier(nil, keys, auth.VerifierOptions{}),
		LocalLogin:         service.NewLocalLoginService(nil, users, sessions, mfa),
		UserSessionService: sessions,
		MFAEnrollment:      enroll,
	})
	return r, expired
}

func postWithBearer(r *gin.Engine, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func expiredBearerUser(t *testing.T) *domain.User {
	t.Helper()
	hash, err := crypto.GenerateHash([]byte("correct"))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return &domain.User{
		ID: uuid.New(), Email: "alice@example.com", Role: domain.RoleOrgUser, OrganizationID: uuid.New(),
		PasswordHash: hash, EmailVerified: true,
	}
}

// Only the methods reached by these four cases are implemented. Embedding
// the interfaces makes any unexpected repository call fail visibly.
type expiredBearerKeyRepo struct {
	repository.KeyRepository
	keys []domain.SigningKey
}

func (r *expiredBearerKeyRepo) GetActiveSigningKeys(context.Context) ([]domain.SigningKey, error) {
	return r.keys, nil
}

type expiredBearerUserRepo struct {
	repository.UserRepository
	user *domain.User
}

func (r *expiredBearerUserRepo) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	return []*domain.User{r.user}, nil
}

type expiredBearerSessionRepo struct{ repository.SessionRepository }

func (*expiredBearerSessionRepo) Create(_ context.Context, session *domain.Session) (*domain.Session, error) {
	session.ID = uuid.New()
	return session, nil
}

type expiredBearerTOTPSteps struct {
	repository.TOTPUsedStepRepository
}

func assertNoSessionMinted(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code == http.StatusOK {
		t.Errorf("%s: status = 200, want a refusal; body=%q", what, w.Body.String())
	}
	if cookies := w.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("%s: %d cookies set, want none", what, len(cookies))
	}
	if strings.Contains(w.Body.String(), "access_token") {
		t.Errorf("%s: response carries an access token", what)
	}
}

func TestLoginRoute_ExpiredBearerDoesNotBlockFreshPassword(t *testing.T) {
	user := expiredBearerUser(t)
	r, expired := expiredBearerEngine(t, user, &domain.MFAPendingLoginSession{})
	w := postWithBearer(r, "/api/v1/auth/login", `{"email":"alice@example.com","password":"correct"}`, expired)
	if w.Code != http.StatusOK {
		t.Fatalf("fresh password with an expired bearer: status = %d body = %q, want 200", w.Code, w.Body.String())
	}
}

func TestLoginRoute_ExpiredBearerWithBadPasswordMintsNothing(t *testing.T) {
	user := expiredBearerUser(t)
	r, expired := expiredBearerEngine(t, user, &domain.MFAPendingLoginSession{})
	w := postWithBearer(r, "/api/v1/auth/login", `{"email":"alice@example.com","password":"wrong"}`, expired)
	assertNoSessionMinted(t, "bad password with an expired bearer", w)
}

func TestLoginMFARoute_ExpiredBearerWithDeadHandleMintsNothing(t *testing.T) {
	user := expiredBearerUser(t)
	consumed := time.Now().Add(-time.Minute)
	for name, row := range map[string]*domain.MFAPendingLoginSession{
		"expired handle": {ID: uuid.New(), UserID: user.ID, Kind: domain.MFAPendingKindVerify,
			CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute)},
		"consumed handle": {ID: uuid.New(), UserID: user.ID, Kind: domain.MFAPendingKindVerify,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute), ConsumedAt: &consumed},
	} {
		r, expired := expiredBearerEngine(t, user, row)
		w := postWithBearer(r, "/api/v1/auth/login/mfa", `{"session_id":"`+row.ID.String()+`","code":"123456"}`, expired)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, w.Code)
		}
		if w.Code == http.StatusUnauthorized && strings.Contains(w.Body.String(), mw.ReasonTokenInvalid) {
			t.Errorf("%s: refused on the stale bearer, want the handle to decide", name)
		}
		assertNoSessionMinted(t, name+" with an expired bearer", w)
	}
}

func TestLogoutRoute_ExpiredBearerStillRefused(t *testing.T) {
	user := expiredBearerUser(t)
	r, expired := expiredBearerEngine(t, user, &domain.MFAPendingLoginSession{})
	w := postWithBearer(r, "/api/v1/auth/logout", `{}`, expired)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), mw.ReasonTokenInvalid) {
		t.Errorf("logout with an expired bearer: status = %d body = %q, want 401 %s", w.Code, w.Body.String(), mw.ReasonTokenInvalid)
	}
}
