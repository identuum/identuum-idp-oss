package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// jwksRoundTripper serves one static JWKS document for the provider JWKS URI,
// so the upstream key resolution is hermetic (no network).
type jwksRoundTripper struct{ body string }

func (rt jwksRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(rt.body)),
		Request:    &http.Request{},
	}, nil
}

// The upstream OIDC callback ID token is accepted ONLY when its signature
// verifies under the provider JWKS AND its issuer, audience and nonce all match
// what we expect: a wrong issuer, an audience that does not contain us, or a
// mismatched nonce is ErrCallbackValidationFailed. A fully-correct token
// round-trips. Reaches validateIDToken directly on a struct whose discovery
// resolves keys from a fake JWKS.
// RULE: CALLBACK-IDTOKEN-VERIFY-1
func TestCallbackIDToken_AcceptedOnlyWithIssuerAudienceNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const kid = "prov-kid"
	jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"` + kid + `","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}]}`

	disc := NewOIDCDiscoveryService(OIDCDiscoveryOptions{
		HTTPClient: &http.Client{Transport: jwksRoundTripper{body: jwks}},
	})
	s := &OIDCCallbackService{discovery: disc, now: time.Now}
	doc := &OIDCDiscoveryDocument{Issuer: "https://prov.test", JWKSURI: "https://prov.test/jwks"}

	const aud, nonce = "our-client-id", "nonce-xyz"
	mint := func(iss, tokenAud, tokenNonce string) string {
		return mintIDToken(t, kid, priv, jwt.MapClaims{
			"iss": iss, "sub": uuid.NewString(), "aud": tokenAud, "nonce": tokenNonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
	}

	// A fully-correct upstream token verifies.
	if _, err := s.validateIDToken(context.Background(), doc, mint("https://prov.test", aud, nonce), aud, nonce); err != nil {
		t.Fatalf("PREMISE FAILED: a valid upstream ID token must verify, got %v", err)
	}
	// A wrong issuer is rejected.
	if _, err := s.validateIDToken(context.Background(), doc, mint("https://evil.test", aud, nonce), aud, nonce); err == nil {
		t.Errorf("a wrong-issuer upstream ID token must fail validation")
	}
	// An audience that does not contain us is rejected.
	if _, err := s.validateIDToken(context.Background(), doc, mint("https://prov.test", "someone-else", nonce), aud, nonce); err == nil {
		t.Errorf("an ID token whose audience does not contain us must fail validation")
	}
	// A mismatched nonce is rejected.
	if _, err := s.validateIDToken(context.Background(), doc, mint("https://prov.test", aud, "wrong-nonce"), aud, nonce); err == nil {
		t.Errorf("a nonce-mismatched ID token must fail validation")
	}
}
