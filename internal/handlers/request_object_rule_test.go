package handlers

// request_object_rule_test.go — RULE: REQUEST-OBJECT-VERIFIED-1
// (THE-JAR-REQUEST-OBJECT), against production wiring of /authorize:
//
//  1. an unverifiable request object never mints — a tampered signature,
//     an unknown key or a symmetric alg answers invalid_request_object
//     (redirected only to the REGISTERED query redirect_uri; a direct 400
//     when the query redirect_uri is not registered — never an open
//     redirect) and no code exists;
//  2. a verified object's parameters land through the SAME path the query
//     uses — the object's redirect_uri/state supersede the query's and the
//     code goes to the object's registered redirect_uri; an object-carried
//     `claims` request reaches the consent gate;
//  3. parameter smuggling is refused — client_id in the object that differs
//     from the query, response_type that contradicts the query, or
//     request/request_uri nested inside;
//  4. an unsigned (alg none) object by value is accepted and mints.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type roTestKeys struct {
	priv ed25519.PrivateKey
	jwks string
}

func newRoTestKeys(t *testing.T) roTestKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(pub)}}})
	return roTestKeys{priv: priv, jwks: string(jwks)}
}

func (k roTestKeys) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unsignedRO(t *testing.T, claims map[string]any) string {
	t.Helper()
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

// requestObjectEngine: /authorize with the request-object service wired,
// a client holding an inline Ed25519 JWKS and two registered redirect URIs.
func requestObjectEngine(t *testing.T, jwks string, skipConsent bool) (*gin.Engine, *domain.Client) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	client := &domain.Client{ClientID: "cli-1", Name: "RO", RedirectURIs: []string{"https://app.example.com/cb", "https://app.example.com/cb2"}, SkipConsent: skipConsent, Scope: "openid profile", JWKS: jwks}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	svc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"})
	if !skipConsent {
		svc = svc.WithConsentService(service.NewConsentService(nil, &captureConsentRepo{}))
	}
	r := gin.New()
	principal := authorizePrincipal()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, principal); c.Next() })
	RegisterAuthorizeRoutes(r, AuthorizeHandlerDeps{
		AuthorizeService: svc,
		Audit:            &audit.Recorder{},
		RequestObjects:   service.NewRequestObjectService(clients, nil, "https://idp.test"),
	})
	return r, client
}

func authorizeWithObject(r *gin.Engine, object string, extra map[string]string) *httptest.ResponseRecorder {
	q := url.Values{"client_id": {"cli-1"}, "response_type": {"code"}, "redirect_uri": {"https://app.example.com/cb"}, "scope": {"openid"}, "state": {"q-state"}, "request": {object}}
	for k, v := range extra {
		q.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/authorize?"+q.Encode(), nil))
	return w
}

var roPKCE = map[string]any{"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"}

func withPKCE(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range roPKCE {
		out[k] = v
	}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RULE: REQUEST-OBJECT-VERIFIED-1
func TestRuleRequestObjectVerified1_UnverifiableNeverMints_VerifiedLandsThroughSharedPath_SmugglingRefused(t *testing.T) {
	keys := newRoTestKeys(t)
	r, _ := requestObjectEngine(t, keys.jwks, true)
	good := withPKCE(map[string]any{"redirect_uri": "https://app.example.com/cb2", "state": "o-state", "nonce": "n"})

	// ── Prong 1: unverifiable → invalid_request_object, no code.
	signed := keys.sign(t, good)
	for name, obj := range map[string]string{
		"tampered signature": signed[:len(signed)-4] + "AAAA",
		"unknown kid":        strings.Replace(signed, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`)), base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k9","typ":"JWT"}`)), 1),
		"symmetric alg":      mustHS256(t, good),
	} {
		w := authorizeWithObject(r, obj, nil)
		loc := w.Header().Get("Location")
		if w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example.com/cb?") || !strings.Contains(loc, "error=invalid_request_object") || strings.Contains(loc, "code=") {
			t.Fatalf("%s: status=%d location=%q, want 302 to the QUERY redirect_uri with error=invalid_request_object and no code", name, w.Code, loc)
		}
		if !strings.Contains(loc, "state=q-state") {
			t.Fatalf("%s: the error redirect must echo the QUERY state (the object was not trusted): %q", name, loc)
		}
	}
	// Unregistered QUERY redirect_uri + unverifiable object → direct 400, never a redirect.
	w := authorizeWithObject(r, signed[:len(signed)-4]+"AAAA", map[string]string{"redirect_uri": "https://evil.example/cb"})
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
		t.Fatalf("unregistered query redirect_uri: status=%d location=%q, want 400 direct", w.Code, w.Header().Get("Location"))
	}

	// ── Prong 2: verified → the object's parameters drive the SAME path:
	// code to the object's redirect_uri (cb2), object's state echoed.
	w = authorizeWithObject(r, signed, nil)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example.com/cb2?") || !strings.Contains(loc, "code=") || !strings.Contains(loc, "state=o-state") {
		t.Fatalf("verified object: status=%d location=%q, want a code at the OBJECT's redirect_uri with the object's state", w.Code, loc)
	}
	// The object's `claims` request reaches the consent gate exactly as a
	// query claims parameter would (non-preapproved client → consent form
	// carrying claims=).
	rc, _ := requestObjectEngine(t, keys.jwks, false)
	w = authorizeWithObject(rc, keys.sign(t, withPKCE(map[string]any{"claims": map[string]any{"userinfo": map[string]any{"name": nil}}})), nil)
	loc = w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "/api/v1/oauth/consent?") || !strings.Contains(loc, "claims=") || strings.Contains(loc, "request=") {
		t.Fatalf("object claims: status=%d location=%q, want the consent redirect carrying claims= (and no raw request=)", w.Code, loc)
	}

	// ── Prong 3: smuggling refused.
	for name, obj := range map[string]string{
		"client_id differs":     keys.sign(t, withPKCE(map[string]any{"client_id": "cli-2"})),
		"response_type differs": keys.sign(t, withPKCE(map[string]any{"response_type": "token"})),
		"nested request":        keys.sign(t, withPKCE(map[string]any{"request": "x"})),
		"nested request_uri":    keys.sign(t, withPKCE(map[string]any{"request_uri": "https://x"})),
	} {
		w := authorizeWithObject(r, obj, nil)
		loc := w.Header().Get("Location")
		if w.Code != http.StatusFound || !strings.Contains(loc, "error=invalid_request_object") || strings.Contains(loc, "code=") {
			t.Fatalf("%s: status=%d location=%q, want invalid_request_object and no code", name, w.Code, loc)
		}
	}

	// ── Prong 4: unsigned (alg none) by value is accepted and mints at the
	// object's redirect_uri — no authority a query string lacks.
	w = authorizeWithObject(r, unsignedRO(t, good), nil)
	loc = w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example.com/cb2?") || !strings.Contains(loc, "code=") {
		t.Fatalf("unsigned object: status=%d location=%q, want a code at the object's redirect_uri", w.Code, loc)
	}
	// request_uri stays refused.
	w = authorizeWithObject(r, "", map[string]string{"request_uri": "https://rp.example/ro.jwt"})
	if loc := w.Header().Get("Location"); w.Code != http.StatusFound || !strings.Contains(loc, "error=request_uri_not_supported") {
		t.Fatalf("request_uri: status=%d location=%q, want request_uri_not_supported", w.Code, loc)
	}
}

func mustHS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
