package handlers

import (
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

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// RP-initiated logout accepts an id_token_hint whose exp has passed (OIDC
// RP-Initiated Logout 1.0 §2): the person is logging out because they have been
// away. A hint that fails its signature or issuer is still a 400.
func TestLogout_AnExpiredHintStillLogsOut(t *testing.T) {
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
	sessions := service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
	cookies := service.NewCookieSessionService(nil, sessions, &fakeUserLookup{user: &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}}, service.CookieSessionServiceOptions{AllowPlainHTTP: true})
	r := gin.New()
	RegisterEndSessionRoutes(r, EndSessionHandlerDeps{
		CookieSession:   cookies,
		UserSession:     sessions,
		Clients:         &fakeLogoutClientLookup{client: &domain.Client{ClientID: "cli-1"}},
		IDTokenVerifier: service.NewIDTokenVerifier(nil, keys, service.IDTokenVerifierOptions{Issuer: "https://idp.test"}),
		Audit:           &audit.Recorder{},
	})

	hint := func(iss string, exp time.Time) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": iss, "sub": uuid.New().String(), "aud": []string{"cli-1"},
			"exp": exp.Unix(), "iat": exp.Add(-time.Hour).Unix(),
		})
		tok.Header["kid"] = "kid-eddsa"
		signed, err := tok.SignedString(priv)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}
	logout := func(h string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/logout?id_token_hint="+h, nil))
		return w
	}

	if w := logout(hint("https://idp.test", time.Now().Add(-48*time.Hour))); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "You are signed out") {
		t.Errorf("an expired hint = %d; want the signed-out page", w.Code)
	}
	if w := logout(hint("https://evil.test", time.Now().Add(-48*time.Hour))); w.Code != http.StatusBadRequest {
		t.Errorf("an expired hint from another issuer = %d; want 400", w.Code)
	}
	if w := logout(hint("https://idp.test", time.Now().Add(-48*time.Hour)) + "x"); w.Code != http.StatusBadRequest {
		t.Errorf("an expired hint with a broken signature = %d; want 400", w.Code)
	}
}
