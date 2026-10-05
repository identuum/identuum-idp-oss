package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// FUNC-M3: the console's code step (POST /api/v1/auth/login/mfa) answers a
// spent per-user wrong-code bound with the sign-in wait, 429 login_throttled
// and Retry-After, not 401 invalid_code — the right code included.

type spentBoundPendingRepo struct {
	recoveryPendingRepoStub
	row *domain.MFAPendingLoginSession
}

func (s spentBoundPendingRepo) GetByID(context.Context, uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	cp := *s.row
	return &cp, nil
}

// Five misses, the oldest on a handle created two minutes ago.
func (s spentBoundPendingRepo) CountRecentFailedVerifyAttempts(context.Context, uuid.UUID, time.Time) (int, time.Time, error) {
	return 5, time.Now().Add(-2 * time.Minute), nil
}

func TestLoginMFARoute_ASpentBoundSaysToWait(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	users := newRecoveryStubUserRepo()
	secret := recoveryTestSeed
	user := &domain.User{ID: uuid.New(), Email: "alice@example.com", MFAEnabled: true, MFASecret: &secret, EmailVerified: true}
	users.byID[user.ID] = user
	pending := spentBoundPendingRepo{row: &domain.MFAPendingLoginSession{
		ID: uuid.New(), UserID: user.ID, Kind: domain.MFAPendingKindVerify,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
	}}
	mfaSvc := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: pending, Users: users, Issuer: "Identuum", Cipher: identityMFACipher{}, Replay: testReplayGuardForHandlers(),
	}, service.MFAEnrollmentServiceOptions{})
	r := gin.New()
	sessions := service.NewUserSessionService(nil, newSessionRepoForHandlers(), service.UserSessionServiceOptions{DefaultTTL: time.Hour})
	RegisterAuthSessionRoutes(r, AuthSessionsHandlerDeps{MFAEnrollment: mfaSvc, UserSession: sessions, Audit: &audit.Recorder{}})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa",
		strings.NewReader(`{"session_id":"`+pending.row.ID.String()+`","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), `"login_throttled"`) {
		t.Fatalf("status = %d body = %q; want 429 login_throttled", w.Code, w.Body.String())
	}
	secs, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || secs < 779 || secs > 781 {
		t.Errorf("Retry-After = %q; want about 780 seconds (13 minutes until the oldest miss leaves the window)", w.Header().Get("Retry-After"))
	}
}
