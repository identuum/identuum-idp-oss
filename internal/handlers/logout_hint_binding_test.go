package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// An id_token_hint vouches for a sign-out only when it belongs to the person
// signed in on this browser (RP-Initiated Logout 1.0 §2: the OP MUST ask when
// the ID Token does not belong to the current session or End-User). The hint
// names its session by `sid`, as the ID tokens this OP issues do, and an access
// token is never a hint.

type hintWorld struct {
	r         *gin.Engine
	sessions  *service.UserSessionService
	cookies   *service.CookieSessionService
	deliverer *recordingDeliverer
	priv      ed25519.PrivateKey
	user      *domain.User // the person signed in on the browser
}

func newHintWorld(t *testing.T, rps rpsFake, bearer *domain.Principal) hintWorld {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(priv.Public())
	pkBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keys := &inMemoryKeyRepoForLogout{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkBytes})),
		State:      domain.KeyStateActive,
	}}}
	user := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: user}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	deliverer := &recordingDeliverer{}
	deps := EndSessionHandlerDeps{
		CookieSession:   cookies,
		UserSession:     sessions,
		Clients:         clientsByClientID{"cli-1": {ClientID: "cli-1"}, "app-b": {ClientID: "app-b", BackchannelLogoutURI: "https://b.example/bc"}},
		IDTokenVerifier: service.NewIDTokenVerifier(nil, keys, service.IDTokenVerifierOptions{Issuer: "https://idp.test"}),
		Audit:           &audit.Recorder{},
	}
	if rps != nil {
		deps.SessionRPs = rps
		deps.BackchannelDelivery = deliverer
	}
	r := gin.New()
	if bearer != nil {
		r.Use(func(c *gin.Context) { mw.SetPrincipal(c, bearer); c.Next() })
	}
	RegisterEndSessionRoutes(r, deps)
	return hintWorld{r: r, sessions: sessions, cookies: cookies, deliverer: deliverer, priv: priv, user: user}
}

// sign returns a token signed by the OP's key with the given claims added to
// iss, aud and a lifetime.
func (w hintWorld) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	all := jwt.MapClaims{"iss": "https://idp.test", "aud": []string{"cli-1"}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		all[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, all)
	tok.Header["kid"] = "kid-eddsa"
	signed, err := tok.SignedString(w.priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// signIn creates a session for userID and returns its cookie (not sent unless
// a test sends it) and the session id.
func (w hintWorld) signIn(t *testing.T, userID uuid.UUID) (*http.Cookie, uuid.UUID) {
	t.Helper()
	issued, err := w.sessions.CreateUserSession(context.Background(), service.CreateUserSessionInput{UserID: userID})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	return w.cookies.Issue(issued.RefreshToken, issued.ExpiresAt), issued.Session.ID
}

func (w hintWorld) alive(cookie *http.Cookie) bool {
	resolved, _ := w.cookies.Resolve(context.Background(), cookie.Value)
	return resolved != nil
}

func (w hintWorld) logout(hint string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout?id_token_hint="+url.QueryEscape(hint), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	return rec
}

func asksToConfirm(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "Sign out?")
}

func signedOut(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "You are signed out")
}

func TestEndSession_AHintForAnotherPersonStillAsks(t *testing.T) {
	w := newHintWorld(t, nil, nil)
	cookie, sid := w.signIn(t, w.user.ID)

	someoneElse := w.sign(t, jwt.MapClaims{"sub": uuid.NewString()})
	if rec := w.logout(someoneElse, cookie); !asksToConfirm(rec) || !w.alive(cookie) {
		t.Errorf("a valid hint for another person = %d; want the confirmation page and the session alive", rec.Code)
	}

	otherSession := w.sign(t, jwt.MapClaims{"sub": w.user.ID.String(), "sid": uuid.NewString()})
	if rec := w.logout(otherSession, cookie); !asksToConfirm(rec) || !w.alive(cookie) {
		t.Errorf("a hint for another session of the same person = %d; want the confirmation page", rec.Code)
	}

	thisSession := w.sign(t, jwt.MapClaims{"sub": w.user.ID.String(), "sid": sid.String()})
	if rec := w.logout(thisSession, cookie); !signedOut(rec) || w.alive(cookie) {
		t.Errorf("a hint for this browser's session = %d; want signed out at once", rec.Code)
	}
}

func TestEndSession_AHintWithoutSidVouchesForItsSubject(t *testing.T) {
	w := newHintWorld(t, nil, nil)
	cookie, _ := w.signIn(t, w.user.ID)
	// An ID token issued before sid existed names only its subject.
	if rec := w.logout(w.sign(t, jwt.MapClaims{"sub": w.user.ID.String()}), cookie); !signedOut(rec) || w.alive(cookie) {
		t.Errorf("a hint for this person without sid = %d; want signed out at once", rec.Code)
	}
}

// The ID tokens this OP issues name their session by sid. With no cookie (a
// browser that has been closed), the hint alone ends that session and its
// relying parties are told.
func TestEndSession_TheHintsSidEndsThatSession(t *testing.T) {
	other := uuid.New()
	w := newHintWorld(t, nil, nil)
	cookie, sid := w.signIn(t, other)
	w = newHintWorldSharing(t, w, rpsFake{sid: {"app-b"}})

	if rec := w.logout(w.sign(t, jwt.MapClaims{"sub": other.String(), "sid": sid.String()}), nil); !signedOut(rec) {
		t.Fatalf("logout with the hint alone = %d; want the signed-out page", rec.Code)
	}
	if w.alive(cookie) {
		t.Error("the session the hint's sid names is still alive")
	}
	if len(w.deliverer.calls) != 1 || w.deliverer.calls[0].SessionID != sid || w.deliverer.calls[0].Subject != other {
		t.Errorf("back-channel deliveries = %+v; want one for session %s subject %s", w.deliverer.calls, sid, other)
	}
}

func TestEndSession_AnAccessTokenIsNotAHint(t *testing.T) {
	w := newHintWorld(t, nil, nil)
	_, sid := w.signIn(t, w.user.ID)
	for name, claims := range map[string]jwt.MapClaims{
		"user access token":        {"sub": w.user.ID.String(), "actor_type": "user", "session_id": sid.String(), "client_id": "cli-1"},
		"refreshed access token":   {"sub": w.user.ID.String(), "client_id": "cli-1", "scope": "openid"},
		"client-credentials token": {"sub": "cli-1", "client_id": "cli-1", "scope": "m2m:read"},
	} {
		if rec := w.logout(w.sign(t, claims), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s as id_token_hint = %d; want 400", name, rec.Code)
		}
	}
}

// Each ended session's logout token names that session's own user: a bearer
// session of another person is not announced under the cookie's user.
func TestEndSession_EachEndedSessionIsAnnouncedForItsOwnUser(t *testing.T) {
	bearerUser, bearerSession := uuid.New(), uuid.New()
	w := newHintWorld(t, rpsFake{bearerSession: {"app-b"}}, &domain.Principal{UserID: bearerUser, SessionID: bearerSession})
	cookie, _ := w.signIn(t, w.user.ID)

	req := httptest.NewRequest(http.MethodGet, confirmedLogoutURL("/api/v1/oidc/logout", cookie), nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.r.ServeHTTP(rec, req)
	if !signedOut(rec) {
		t.Fatalf("confirmed logout = %d; want the signed-out page", rec.Code)
	}
	if len(w.deliverer.calls) != 1 || w.deliverer.calls[0].SessionID != bearerSession || w.deliverer.calls[0].Subject != bearerUser {
		t.Errorf("back-channel deliveries = %+v; want one for the bearer's session naming the bearer's user %s", w.deliverer.calls, bearerUser)
	}
}

// newHintWorldSharing rebuilds the engine over w's stores and keys with the
// given relying parties recorded.
func newHintWorldSharing(t *testing.T, w hintWorld, rps rpsFake) hintWorld {
	t.Helper()
	pubBytes, _ := x509.MarshalPKIXPublicKey(w.priv.Public())
	pkBytes, _ := x509.MarshalPKCS8PrivateKey(w.priv)
	keys := &inMemoryKeyRepoForLogout{keys: []domain.SigningKey{{
		KID: "kid-eddsa", Algorithm: domain.KeyAlgorithmEdDSA,
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkBytes})),
		State:      domain.KeyStateActive,
	}}}
	deliverer := &recordingDeliverer{}
	r := gin.New()
	RegisterEndSessionRoutes(r, EndSessionHandlerDeps{
		CookieSession:       w.cookies,
		UserSession:         w.sessions,
		Clients:             clientsByClientID{"cli-1": {ClientID: "cli-1"}, "app-b": {ClientID: "app-b", BackchannelLogoutURI: "https://b.example/bc"}},
		IDTokenVerifier:     service.NewIDTokenVerifier(nil, keys, service.IDTokenVerifierOptions{Issuer: "https://idp.test"}),
		SessionRPs:          rps,
		BackchannelDelivery: deliverer,
		Audit:               &audit.Recorder{},
	})
	w.r, w.deliverer = r, deliverer
	return w
}
