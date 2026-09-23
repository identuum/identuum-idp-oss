package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

type browserRefreshRepo struct {
	*inMemorySessionRepoForHandlers
	mu        sync.Mutex
	statusErr error
	barrier   chan struct{}
	reads     int
}

func (r *browserRefreshRepo) GetByTokenSelector(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	r.mu.Lock()
	s, err := r.inMemorySessionRepoForHandlers.GetByTokenSelector(ctx, id)
	r.reads++
	reads, barrier := r.reads, r.barrier
	if barrier != nil && reads == 2 {
		close(barrier)
	}
	r.mu.Unlock()
	if barrier != nil && reads <= 2 {
		<-barrier
	}
	return s, err
}

func (r *browserRefreshRepo) GetSessionWithUserAndOrgStatus(ctx context.Context, id uuid.UUID) (*domain.SessionValidationInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.statusErr != nil {
		return nil, r.statusErr
	}
	s, err := r.inMemorySessionRepoForHandlers.GetByID(ctx, id)
	return &domain.SessionValidationInfo{Session: s, UserActive: true, OrgActive: true}, err
}

func (r *browserRefreshRepo) RotateToken(ctx context.Context, id uuid.UUID, expected, next string, expires, used time.Time) (*domain.Session, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, won, err := r.inMemorySessionRepoForHandlers.RotateToken(ctx, id, expected, next, expires, used)
	if won {
		r.byID[id].PrevValidatorHash = &expected
		r.byID[id].PrevRotatedAt = &used
	}
	return s, won, err
}

type browserRefreshMinter struct {
	mu     sync.Mutex
	claims []oidc.TokenClaims
	err    error
}

func (m *browserRefreshMinter) Mint(_ context.Context, c oidc.TokenClaims) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claims = append(m.claims, c)
	return "synthetic-access", "synthetic-key", m.err
}

func browserRefreshFixture(t *testing.T) (*gin.Engine, *browserRefreshRepo, *browserRefreshMinter, *service.IssuedUserSession) {
	t.Helper()
	r := &browserRefreshRepo{inMemorySessionRepoForHandlers: newSessionRepoForHandlers()}
	svc := service.NewUserSessionService(nil, r, service.UserSessionServiceOptions{})
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser, Email: "fixture@example.test"}
	issued, err := svc.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: user.ID, Acr: "urn:identuum:acr:mfa", Amr: []string{"pwd", "otp"}})
	if err != nil {
		t.Fatal("fixture session creation failed")
	}
	m := &browserRefreshMinter{}
	signer := service.NewUserTokenService(nil, userTokenKeyProvider(t), service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: 15 * time.Minute, Minter: m})
	e := gin.New()
	e.POST("/refresh", HandleBrowserSessionRefresh(AuthSessionsHandlerDeps{UserSession: svc, UserToken: signer, UserLookup: &inMemoryUserByIDLookup{byID: map[uuid.UUID]*domain.User{user.ID: user}}}))
	return e, r, m, issued
}

func browserRefreshRequest(e http.Handler, raw string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://idp.test/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: raw})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestBrowserRefresh_ConcurrentRotationNeverOverwritesWinnerCookie(t *testing.T) {
	e, r, m, issued := browserRefreshFixture(t)
	r.barrier = make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { results <- browserRefreshRequest(e, issued.RefreshToken) }()
	}
	refreshCookies := 0
	for range 2 {
		rec := <-results
		if rec.Code != 204 || rec.Body.Len() != 0 {
			t.Error("concurrent refresh must return empty successful response")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Error("refresh response permits caching")
		}
		for _, c := range rec.Result().Cookies() {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
				t.Error("refresh cookie lost security attributes")
			}
			if c.Name == "refresh_token" {
				refreshCookies++
				if c.Value == issued.RefreshToken {
					t.Error("predecessor overwrote winner cookie")
				}
				if c.MaxAge != 0 {
					t.Error("refresh turned a browser session into a persistent session")
				}
			}
		}
	}
	if refreshCookies != 1 {
		t.Error("exactly the CAS winner must set a successor refresh cookie")
	}
	if len(m.claims) != 2 {
		t.Fatal("both accepted refreshes must issue access credentials")
	}
	for _, c := range m.claims {
		if c.Extra["auth_time"] != issued.Session.EffectiveAuthTime().Unix() || c.Extra["acr"] != issued.Session.EffectiveACR() {
			t.Error("refresh changed original authentication assurance")
		}
		if c.ExpiresAt.Sub(c.IssuedAt) != 15*time.Minute {
			t.Error("refresh extended access-token lifetime")
		}
	}
}

func TestBrowserRefresh_FailuresDoNotAcceptOrChangeCookies(t *testing.T) {
	for _, failure := range []string{"store", "revoked", "signer", "expired", "missing"} {
		t.Run(failure, func(t *testing.T) {
			e, r, m, issued := browserRefreshFixture(t)
			want, raw := 503, issued.RefreshToken
			switch failure {
			case "store":
				r.statusErr = errors.New("fixture unavailable")
			case "revoked":
				r.byID[issued.Session.ID].IsValid = false
				want = 401
			case "expired":
				r.byID[issued.Session.ID].ExpiresAt = time.Now().Add(-time.Hour)
				want = 401
			case "signer":
				m.err = errors.New("fixture unavailable")
			case "missing":
				raw = ""
				want = 401
			}
			rec := browserRefreshRequest(e, raw)
			if rec.Code != want {
				t.Errorf("status = %d, want %d", rec.Code, want)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("failed refresh changed cookies")
			}
			if failure != "signer" && len(m.claims) != 0 {
				t.Error("failed session check reached access-token minting")
			}
		})
	}
}
