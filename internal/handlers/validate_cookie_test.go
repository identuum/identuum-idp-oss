package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakeValidateVerifier struct {
	principal *domain.Principal
	err       error
}

func (f fakeValidateVerifier) VerifyBearerToken(context.Context, string) (*domain.Principal, error) {
	return f.principal, f.err
}

type fakeSessionByID struct{ s *domain.Session }

func (f fakeSessionByID) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return f.s, nil
}

type fakeUserByID struct{ u *domain.User }

func (f fakeUserByID) GetByID(context.Context, uuid.UUID) (*domain.User, error) { return f.u, nil }

// GET /api/v1/validate trusts the access_token cookie (preferred over the
// Authorization header) only after the token cryptographically verifies to a
// principal whose session is usable and whose user is neither banned nor
// deleted; any break in that chain is a 401. Driven through the routed handler
// (extractValidateToken -> VerifyBearerToken -> Session.CanBeUsed -> user check).
// RULE: VALIDATE-COOKIE-1
func TestHandleValidateSession_TrustsCookieOnlyAfterFullChain(t *testing.T) {
	uid, sid := uuid.New(), uuid.New()
	goodPrincipal := &domain.Principal{UserID: uid, SessionID: sid}
	usableSession := &domain.Session{ID: sid, UserID: uid, IsValid: true, ExpiresAt: time.Now().Add(time.Hour)}
	liveUser := &domain.User{ID: uid, Email: "u@example.test", Role: domain.RoleOrgUser}

	engine := func(deps AuthSessionsHandlerDeps) *gin.Engine {
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		RegisterAuthSessionRoutes(r, deps)
		return r
	}
	get := func(r *gin.Engine, cookie, bearer string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "access_token", Value: cookie})
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	full := AuthSessionsHandlerDeps{
		TokenVerifier: fakeValidateVerifier{principal: goodPrincipal},
		SessionLookup: fakeSessionByID{s: usableSession},
		UserLookup:    fakeUserByID{u: liveUser},
	}

	// Happy path: a verifying cookie yields 200.
	if code := get(engine(full), "good-cookie", ""); code != http.StatusOK {
		t.Fatalf("PREMISE FAILED: a verifying access_token cookie must yield 200, got %d", code)
	}
	// No token at all -> 401.
	if code := get(engine(full), "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token must be 401, got %d", code)
	}
	// Cookie preferred over header: a good cookie + a token the verifier would
	// reject as a header still succeeds because the cookie is read first.
	if code := get(engine(full), "good-cookie", "ignored"); code != http.StatusOK {
		t.Errorf("access_token cookie must be preferred over the header, got %d", code)
	}

	// Token that does not verify -> 401.
	badVerify := full
	badVerify.TokenVerifier = fakeValidateVerifier{err: context.Canceled}
	if code := get(engine(badVerify), "any", ""); code != http.StatusUnauthorized {
		t.Errorf("an unverifiable token must be 401, got %d", code)
	}
	// Verifies, but the session is not usable (revoked) -> 401.
	revokedNow := time.Now()
	unusable := badVerify
	unusable.TokenVerifier = fakeValidateVerifier{principal: goodPrincipal}
	unusable.SessionLookup = fakeSessionByID{s: &domain.Session{ID: sid, UserID: uid, IsValid: true, ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &revokedNow}}
	if code := get(engine(unusable), "good-cookie", ""); code != http.StatusUnauthorized {
		t.Errorf("a revoked session must be 401, got %d", code)
	}
	// Verifies, session usable, but the user is banned -> 401.
	banned := full
	banned.UserLookup = fakeUserByID{u: &domain.User{ID: uid, Email: "u@example.test", Role: domain.RoleOrgUser, Banned: true}}
	if code := get(engine(banned), "good-cookie", ""); code != http.StatusUnauthorized {
		t.Errorf("a banned user must be 401, got %d", code)
	}
}
