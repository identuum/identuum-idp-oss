package service

// request_object_service_test.go — THE-JAR-REQUEST-OBJECT: unsigned (none)
// and signed request objects resolve into merged parameters; anything that
// cannot be verified is refused; §6.1 agreement rules hold.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type roKeys struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	jwks string
}

func newROKeys(t *testing.T, kid string) roKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
	return roKeys{pub: pub, priv: priv, jwks: string(jwks)}
}

func (k roKeys) sign(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unsignedObject(t *testing.T, claims map[string]any) string {
	t.Helper()
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p, _ := json.Marshal(claims)
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

// roClientLookup answers only its own client_id (the shared fake ignores
// the id, which would hide the unknown-client branch).
type roClientLookup struct{ client *domain.Client }

func (l roClientLookup) GetClientByClientID(_ context.Context, id string) (*domain.Client, error) {
	if l.client == nil || l.client.ClientID != id {
		return nil, errors.New("not found")
	}
	return l.client, nil
}

func roHarness(t *testing.T, jwks string) (*RequestObjectService, *domain.Client) {
	t.Helper()
	client := &domain.Client{ClientID: "cli-1", RedirectURIs: []string{"https://app.example.com/cb", "https://app.example.com/cb2"}, JWKS: jwks}
	svc := NewRequestObjectService(roClientLookup{client: client}, nil, "https://idp.test/").
		WithClock(func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) })
	return svc, client
}

func baseQuery(request string) url.Values {
	return url.Values{
		"client_id": {"cli-1"}, "response_type": {"code"}, "redirect_uri": {"https://app.example.com/cb"},
		"scope": {"openid"}, "state": {"q-state"}, "request": {request},
	}
}

func TestRequestObject_UnsignedByValueMergesAndSupersedes(t *testing.T) {
	svc, _ := roHarness(t, "")
	obj := unsignedObject(t, map[string]any{
		"client_id": "cli-1", "response_type": "code", "redirect_uri": "https://app.example.com/cb2",
		"state": "o-state", "nonce": "n1", "max_age": 60, "acr_values": "urn:identuum:loa:mfa",
		"claims":         map[string]any{"userinfo": map[string]any{"name": nil}},
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256",
	})
	merged, safe, err := svc.Resolve(context.Background(), baseQuery(obj))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !safe {
		t.Errorf("query redirect_uri is registered → redirectSafe must be true")
	}
	if merged.Get("request") != "" || merged.Get("redirect_uri") != "https://app.example.com/cb2" || merged.Get("state") != "o-state" {
		t.Errorf("object members must supersede the query and request must be dropped: %v", merged)
	}
	if merged.Get("max_age") != "60" || merged.Get("acr_values") != "urn:identuum:loa:mfa" || merged.Get("nonce") != "n1" {
		t.Errorf("stringified members: %v", merged)
	}
	if !strings.Contains(merged.Get("claims"), `"userinfo"`) {
		t.Errorf("claims member must be re-serialized JSON: %q", merged.Get("claims"))
	}
	if merged.Get("scope") != "openid" {
		t.Errorf("query-only parameters must survive: %v", merged)
	}
}

func TestRequestObject_SignedVerifiesAgainstRegisteredKeys(t *testing.T) {
	k := newROKeys(t, "k1")
	svc, _ := roHarness(t, k.jwks)
	obj := k.sign(t, "k1", map[string]any{"iss": "cli-1", "aud": "https://idp.test", "exp": time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC).Unix(), "state": "signed"})
	merged, _, err := svc.Resolve(context.Background(), baseQuery(obj))
	if err != nil || merged.Get("state") != "signed" {
		t.Fatalf("signed object must resolve: err=%v merged=%v", err, merged)
	}
	for _, envelope := range []string{"iss", "aud", "exp"} {
		if merged.Get(envelope) != "" {
			t.Errorf("%s is an envelope claim, not an authorize parameter: %v", envelope, merged)
		}
	}
	// kid absent with a single registered key still resolves.
	if _, _, err := svc.Resolve(context.Background(), baseQuery(k.sign(t, "", map[string]any{"state": "nokid"}))); err != nil {
		t.Errorf("single-key JWKS without kid must resolve: %v", err)
	}
}

// RULE: REQUEST-OBJECT-VERIFIED-1 (service prong) — unverifiable objects
// never resolve, and the §6.1 agreement rules refuse smuggling.
func TestRequestObject_UnverifiableAndSmugglingRefused(t *testing.T) {
	k := newROKeys(t, "k1")
	other := newROKeys(t, "k1")
	svc, _ := roHarness(t, k.jwks)
	good := map[string]any{"state": "x"}
	cases := map[string]string{
		"tampered signature":        k.sign(t, "k1", good)[:len(k.sign(t, "k1", good))-4] + "AAAA",
		"signed by another key":     other.sign(t, "k1", good),
		"unknown kid":               k.sign(t, "k2", good),
		"symmetric alg":             hs256Object(t, good),
		"garbage":                   "not.a.jws.at.all",
		"none with a signature":     unsignedObject(t, good) + "sig",
		"iss is not the client":     k.sign(t, "k1", map[string]any{"iss": "someone-else"}),
		"aud is not this issuer":    k.sign(t, "k1", map[string]any{"aud": "https://other.example"}),
		"expired":                   k.sign(t, "k1", map[string]any{"exp": time.Date(2026, 9, 2, 11, 0, 0, 0, time.UTC).Unix()}),
		"client_id smuggled":        unsignedObject(t, map[string]any{"client_id": "cli-2"}),
		"response_type contradicts": unsignedObject(t, map[string]any{"response_type": "token"}),
		"request inside the object": unsignedObject(t, map[string]any{"request": "nested"}),
		"request_uri inside":        unsignedObject(t, map[string]any{"request_uri": "https://x"}),
	}
	for name, obj := range cases {
		t.Run(name, func(t *testing.T) {
			merged, _, err := svc.Resolve(context.Background(), baseQuery(obj))
			if !errors.Is(err, ErrAuthorizeInvalidRequestObject) || merged != nil {
				t.Fatalf("err = %v merged=%v, want ErrAuthorizeInvalidRequestObject and no merge", err, merged)
			}
		})
	}
	t.Run("unknown client → invalid_client (direct, no trusted redirect)", func(t *testing.T) {
		q := baseQuery(unsignedObject(t, good))
		q.Set("client_id", "ghost")
		_, safe, err := svc.Resolve(context.Background(), q)
		if !errors.Is(err, ErrAuthorizeInvalidClient) || safe {
			t.Fatalf("err = %v safe=%v", err, safe)
		}
	})
	t.Run("unregistered query redirect_uri → not redirect-safe", func(t *testing.T) {
		q := baseQuery(k.sign(t, "k2", good))
		q.Set("redirect_uri", "https://evil.example/cb")
		_, safe, err := svc.Resolve(context.Background(), q)
		if !errors.Is(err, ErrAuthorizeInvalidRequestObject) || safe {
			t.Fatalf("err = %v safe=%v, want invalid_request_object and redirectSafe=false", err, safe)
		}
	})
	t.Run("no request → query unchanged", func(t *testing.T) {
		q := baseQuery("")
		q.Del("request")
		merged, _, err := svc.Resolve(context.Background(), q)
		if err != nil || merged.Get("state") != "q-state" {
			t.Fatalf("err=%v merged=%v", err, merged)
		}
	})
}

func hs256Object(t *testing.T, claims map[string]any) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequestObjectSigningAlgValuesSupported_NoneAndAsymmetricOnly(t *testing.T) {
	algs := RequestObjectSigningAlgValuesSupported()
	if algs[0] != "none" {
		t.Fatalf("none first: %v", algs)
	}
	for _, a := range algs[1:] {
		if strings.HasPrefix(a, "HS") {
			t.Fatalf("symmetric alg advertised: %v", algs)
		}
		if _, ok := domain.PrivateKeyJWTSigningAlgorithms[a]; !ok {
			t.Fatalf("%s is not in the asymmetric allow-list", a)
		}
	}
}
