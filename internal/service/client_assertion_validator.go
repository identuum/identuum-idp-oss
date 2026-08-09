// Package service — ClientAssertionValidator validates private_key_jwt
// client assertions per RFC 7523 §2.2 / OIDC Core §9 for the OSS build.
//
// Differences from the monolith's validator:
//
//   - Inline JWKS support only. The monolith resolves jwks_uri via a
//     network-fetching AssertionJWKSCache; OSS does NOT include the
//     fetch path in this slice (it would require an HTTP client + TLS
//     policy + retry/backoff that is not yet OSS-extracted). Clients
//     configured with jwks_uri report "private_key_jwt not configurable"
//     for this slice — see WithAudienceLookup-equivalent gating.
//   - Replay detection is intentionally NOT implemented in this slice.
//     The monolith uses a Redis assertionReplayCache; OSS does not yet
//     have a safe replay store wired (oauth_token_revocations has
//     different semantics — it tracks revoked-by-operator jtis, not
//     used-once jtis). The 5-minute max-lifetime + mandatory exp/iat/aud
//     bounds reduces the window; full replay defense is deferred to a
//     follow-up slice.
//   - Inbound algorithm allowlist matches the monolith:
//     EdDSA, ES256, ES384, RS256, RS384, RS512, PS256, PS384, PS512.
//     No `none`, no HS*, no ES512. Identuum DOES NOT issue RS*/PS* — the
//     OSS TokenService still bans RS256 on the outbound path. The set
//     here governs INBOUND verification of externally signed client
//     assertions only.
//   - client_secret_jwt is intentionally NOT supported. OSS stores only
//     the SHA-256 hash of the client secret; HS256 verification requires
//     the raw secret. Operators that need client_secret_jwt must use
//     private_key_jwt instead. See README for the explicit blocker.
package service

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ClientAssertionTypeJWTBearer is the OAuth-registered URN value the
// client_assertion_type form parameter must carry when a caller
// authenticates via private_key_jwt or client_secret_jwt per
// RFC 7523 §2.2 / OIDC Core §9.
//
//nolint:gosec // G101: URN identifier, not a secret.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const (
	clientAssertionDefaultMaxIATAge = 5 * time.Minute
	clientAssertionDefaultClockSkew = 60 * time.Second
	clientAssertionMaxLifetime      = 5 * time.Minute
)

// PrivateKeyJWTAssertionAlgorithms is the slice form of the inbound
// allowlist, exposed for discovery metadata.
var PrivateKeyJWTAssertionAlgorithms = func() []string {
	out := make([]string, 0, len(domain.PrivateKeyJWTSigningAlgorithms))
	for a := range domain.PrivateKeyJWTSigningAlgorithms {
		out = append(out, a)
	}
	return out
}()

// ClientAssertionValidatorConfig parameterises the validator.
type ClientAssertionValidatorConfig struct {
	// TokenEndpointURL is the absolute URL of the IdP's /token
	// endpoint. The assertion's aud claim MUST equal this value
	// (RFC 7523 §3).
	TokenEndpointURL string

	// MaxIATAge is the maximum age of an iat claim. Default 5 min.
	MaxIATAge time.Duration

	// ClockSkew is the tolerance applied to exp/nbf comparisons.
	// Default 60 s.
	ClockSkew time.Duration
}

// ValidatedClientAssertion is the success-path return.
type ValidatedClientAssertion struct {
	Claims jwt.MapClaims
	JTI    string
}

// ClientAssertionReplayDetector is the seam ClientAssertionValidator
// consults to enforce one-use semantics on private_key_jwt
// assertions. *ClientAssertionReplayService satisfies it.
//
// Mark MUST return (true, nil) on first use, (false, nil) on
// replay, and (false, err) on any store-side failure. The validator
// fails CLOSED on both the replay case AND the error case so a
// transient store outage cannot silently weaken replay defense.
type ClientAssertionReplayDetector interface {
	Mark(ctx context.Context, clientID, jti string, assertionExp time.Time) (firstUse bool, err error)
}

// ClientJWKSFetcher is the seam ClientAssertionValidator consults
// when a private_key_jwt client is configured with `jwks_uri`
// instead of inline JWKS. *ClientJWKSFetcherService satisfies it.
//
// Fetch returns the verification key for (jwksURI, kid). Empty kid
// is allowed only when the fetched JWKS contains exactly one key.
// A non-nil error MUST be opaque — callers map it to invalid_client.
type ClientJWKSFetcher interface {
	Fetch(ctx context.Context, jwksURI, kid string) (crypto.PublicKey, error)
}

// ClientAssertionValidator validates private_key_jwt client
// assertions for the OSS build.
type ClientAssertionValidator struct {
	cfg         ClientAssertionValidatorConfig
	now         func() time.Time
	replay      ClientAssertionReplayDetector
	jwksFetcher ClientJWKSFetcher
}

// NewClientAssertionValidator constructs the validator.
// cfg.TokenEndpointURL is required.
func NewClientAssertionValidator(cfg ClientAssertionValidatorConfig) (*ClientAssertionValidator, error) {
	if cfg.TokenEndpointURL == "" {
		return nil, errors.New("service: ClientAssertionValidator requires a non-empty TokenEndpointURL")
	}
	if cfg.MaxIATAge <= 0 {
		cfg.MaxIATAge = clientAssertionDefaultMaxIATAge
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = clientAssertionDefaultClockSkew
	}
	return &ClientAssertionValidator{cfg: cfg, now: time.Now}, nil
}

// WithReplayDetector composes a replay store into the validator.
// nil resets to the no-replay-defense state (only the assertion's
// own short lifetime bounds the replay window — the
// pre-replay-store posture).
//
// Returns the receiver so the call composes with construction.
func (v *ClientAssertionValidator) WithReplayDetector(d ClientAssertionReplayDetector) *ClientAssertionValidator {
	if v == nil {
		return nil
	}
	v.replay = d
	return v
}

// WithJWKSFetcher composes a JWKS URI fetcher into the validator.
// nil resets to the inline-JWKS-only state — clients configured
// with jwks_uri will continue to surface
// ErrClientAssertionUnsupported.
//
// Returns the receiver so the call composes with construction.
func (v *ClientAssertionValidator) WithJWKSFetcher(f ClientJWKSFetcher) *ClientAssertionValidator {
	if v == nil {
		return nil
	}
	v.jwksFetcher = f
	return v
}

// ErrClientAssertionInvalid is the single opaque sentinel returned
// by Validate. The wire layer maps this to the canonical
// `{"error":"invalid_client"}` envelope per RFC 6749 §5.2 so that
// missing-record, wrong-key, expired-assertion, and replay all
// look the same to the caller.
var ErrClientAssertionInvalid = errors.New("service: invalid client assertion")

// ErrClientAssertionUnsupported is returned when the configured
// client uses an authentication method this validator cannot
// satisfy (e.g. jwks_uri without an HTTP fetcher) so the caller
// can surface a different operator-facing message.
var ErrClientAssertionUnsupported = errors.New("service: client assertion method unsupported")

// Validate runs the full validation pipeline for a private_key_jwt
// assertion. Returns ErrClientAssertionInvalid for any verification
// failure; ErrClientAssertionUnsupported when the client is
// configured to use a key source this OSS slice cannot resolve.
//
// The raw assertion JWT is NEVER echoed in the error path or in
// logs from this function.
func (v *ClientAssertionValidator) Validate(ctx context.Context, client *domain.Client, assertionJWT string) (*ValidatedClientAssertion, error) {
	if client == nil || assertionJWT == "" {
		return nil, ErrClientAssertionInvalid
	}

	// 1. Unverified parse to extract header fields.
	unverifiedParser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverifiedClaims := jwt.MapClaims{}
	parsedUnverified, _, err := unverifiedParser.ParseUnverified(assertionJWT, &unverifiedClaims)
	if err != nil {
		return nil, ErrClientAssertionInvalid
	}

	headerAlg, _ := parsedUnverified.Header["alg"].(string)
	kid, _ := parsedUnverified.Header["kid"].(string)

	// Pre-flight: reject none, HS*, and anything outside the inbound
	// allowlist. HS* would map to client_secret_jwt — which the OSS
	// slice does not support — and `none` is unconditionally rejected
	// regardless of any header alg field value.
	if headerAlg == "" || headerAlg == "none" {
		return nil, ErrClientAssertionInvalid
	}
	if strings.HasPrefix(headerAlg, "HS") {
		return nil, ErrClientAssertionInvalid
	}
	if _, ok := domain.PrivateKeyJWTSigningAlgorithms[headerAlg]; !ok {
		return nil, ErrClientAssertionInvalid
	}

	// 2. JWT header alg must match the client's effective configured
	// alg so an attacker who steals the client's RSA key cannot swap
	// to an EdDSA assertion (and vice versa).
	if headerAlg != client.EffectiveSigningAlg() {
		return nil, ErrClientAssertionInvalid
	}

	// 3. iss must equal client_id (RFC 7523 §3).
	iss, _ := unverifiedClaims["iss"].(string)
	if strings.TrimSpace(iss) == "" || iss != client.ClientID {
		return nil, ErrClientAssertionInvalid
	}

	// 4. Resolve verification key from configured key source.
	pubKey, resolveErr := v.resolveKey(ctx, client, kid)
	if resolveErr != nil {
		if errors.Is(resolveErr, ErrClientAssertionUnsupported) {
			return nil, ErrClientAssertionUnsupported
		}
		return nil, ErrClientAssertionInvalid
	}

	// 5. Verify signature with per-assertion algorithm restriction.
	verified := jwt.MapClaims{}
	_, err = jwt.NewParser(
		jwt.WithValidMethods([]string{headerAlg}),
		jwt.WithoutClaimsValidation(),
	).ParseWithClaims(assertionJWT, &verified, func(t *jwt.Token) (any, error) {
		if hkid, _ := t.Header["kid"].(string); hkid != kid {
			return nil, fmt.Errorf("kid changed during parse")
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, ErrClientAssertionInvalid
	}

	// 6. Claim validation.
	now := v.now()

	// sub == client_id.
	sub, _ := verified["sub"].(string)
	if sub == "" || sub != client.ClientID {
		return nil, ErrClientAssertionInvalid
	}

	// aud must contain the configured token endpoint URL.
	tokenAud, err := extractAssertionAudience(verified)
	if err != nil {
		return nil, ErrClientAssertionInvalid
	}
	if !assertionAudienceContains(tokenAud, v.cfg.TokenEndpointURL) {
		return nil, ErrClientAssertionInvalid
	}

	// exp: required.
	exp, err := extractAssertionTime(verified, "exp", true)
	if err != nil || exp == nil {
		return nil, ErrClientAssertionInvalid
	}
	if now.After(exp.Add(v.cfg.ClockSkew)) {
		return nil, ErrClientAssertionInvalid
	}

	// iat: required.
	iat, err := extractAssertionTime(verified, "iat", true)
	if err != nil || iat == nil {
		return nil, ErrClientAssertionInvalid
	}
	if now.Sub(*iat) > v.cfg.MaxIATAge+v.cfg.ClockSkew {
		return nil, ErrClientAssertionInvalid
	}

	// nbf: optional, respected if present.
	nbf, err := extractAssertionTime(verified, "nbf", false)
	if err != nil {
		return nil, ErrClientAssertionInvalid
	}
	if nbf != nil && now.Add(v.cfg.ClockSkew).Before(*nbf) {
		return nil, ErrClientAssertionInvalid
	}

	// Max lifetime: exp - iat must not exceed 5 minutes.
	if exp.Sub(*iat) > clientAssertionMaxLifetime+v.cfg.ClockSkew {
		return nil, ErrClientAssertionInvalid
	}

	// jti: required.
	jti, _ := verified["jti"].(string)
	if strings.TrimSpace(jti) == "" {
		return nil, ErrClientAssertionInvalid
	}

	// 7. Replay detection. Runs AFTER all signature / claims
	// validation so a malformed assertion does NOT pollute the
	// replay store. When a detector is wired:
	//   - first use → continue
	//   - replay    → ErrClientAssertionInvalid
	//   - store err → ErrClientAssertionInvalid (fail-closed)
	// When no detector is wired, the assertion's own short
	// lifetime is the only replay window (the pre-replay-store
	// posture documented in prior slice notes).
	if v.replay != nil {
		firstUse, replayErr := v.replay.Mark(ctx, client.ClientID, jti, *exp)
		if replayErr != nil || !firstUse {
			return nil, ErrClientAssertionInvalid
		}
	}

	return &ValidatedClientAssertion{Claims: verified, JTI: jti}, nil
}

// resolveKey returns the verification key for the assertion from
// the client's configured key source.
//
// Inline JWKS (client.JWKS) is preferred when present — it does
// not require an outbound HTTP fetch. JWKS URI is used when a
// ClientJWKSFetcher is wired via WithJWKSFetcher. When neither
// path is available, the validator surfaces a clean
// ErrClientAssertionUnsupported (jwks_uri configured but no
// fetcher) or ErrClientAssertionInvalid (no key source at all).
func (v *ClientAssertionValidator) resolveKey(ctx context.Context, client *domain.Client, kid string) (crypto.PublicKey, error) {
	if strings.TrimSpace(client.JWKS) != "" {
		return resolveInlineAssertionJWKSKey(client.JWKS, kid)
	}
	if uri := strings.TrimSpace(client.JWKSUri); uri != "" {
		if v.jwksFetcher == nil {
			return nil, ErrClientAssertionUnsupported
		}
		return v.jwksFetcher.Fetch(ctx, uri, kid)
	}
	return nil, ErrClientAssertionInvalid
}

// resolveInlineAssertionJWKSKey finds and parses the key with the
// given kid from an inline JWKS JSON string. If kid is empty and
// the key set contains exactly one key, that key is used.
func resolveInlineAssertionJWKSKey(jwksJSON, kid string) (crypto.PublicKey, error) {
	var doc struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &doc); err != nil {
		return nil, fmt.Errorf("inline JWKS parse: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("inline JWKS: empty key set")
	}
	if kid == "" {
		if len(doc.Keys) != 1 {
			return nil, fmt.Errorf("inline JWKS: kid absent but %d keys present", len(doc.Keys))
		}
		return clientAssertionPublicKeyFromJWK(doc.Keys[0])
	}
	for _, k := range doc.Keys {
		kidVal, _ := k["kid"].(string)
		if kidVal == kid {
			return clientAssertionPublicKeyFromJWK(k)
		}
	}
	return nil, fmt.Errorf("inline JWKS: kid %q not found", kid)
}

// clientAssertionPublicKeyFromJWK parses a single JWK map into a
// crypto.PublicKey. Supported key families match
// domain.PrivateKeyJWTSigningAlgorithms:
//
//   - OKP/Ed25519        → EdDSA
//   - EC/P-256 + EC/P-384 → ES256 / ES384
//   - RSA (≥ 2048-bit)    → RS*/PS*
//
// EC/P-521 and all other curves are rejected. HS* and none are
// never parsed here.
func clientAssertionPublicKeyFromJWK(jwk map[string]interface{}) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "OKP":
		crv, _ := jwk["crv"].(string)
		if crv != "Ed25519" {
			return nil, fmt.Errorf("OKP key with unsupported crv: %q", crv)
		}
		xStr, _ := jwk["x"].(string)
		if xStr == "" {
			return nil, errors.New("OKP/Ed25519 key missing x")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("OKP/Ed25519 x base64 decode: %w", err)
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("OKP/Ed25519 x has wrong length: %d", len(xBytes))
		}
		return ed25519.PublicKey(xBytes), nil

	case "EC":
		crv, _ := jwk["crv"].(string)
		xStr, _ := jwk["x"].(string)
		yStr, _ := jwk["y"].(string)
		if xStr == "" || yStr == "" {
			return nil, fmt.Errorf("EC/%s key missing x or y", crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("EC/%s x base64 decode: %w", crv, err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, fmt.Errorf("EC/%s y base64 decode: %w", crv, err)
		}
		return ecJWKToPublicKeyAssertion(crv, xBytes, yBytes)

	case "RSA":
		nStr, _ := jwk["n"].(string)
		eStr, _ := jwk["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, errors.New("RSA key missing n or e")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, fmt.Errorf("RSA n base64 decode: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, fmt.Errorf("RSA e base64 decode: %w", err)
		}
		n := new(big.Int).SetBytes(nBytes)
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA modulus too small: %d bits (minimum 2048)", n.BitLen())
		}
		eInt := new(big.Int).SetBytes(eBytes)
		if !eInt.IsInt64() {
			return nil, errors.New("RSA exponent does not fit in int64")
		}
		e := int(eInt.Int64())
		if e < 3 {
			return nil, fmt.Errorf("RSA exponent out of range: %d", e)
		}
		return &rsa.PublicKey{N: n, E: e}, nil

	default:
		return nil, fmt.Errorf("unsupported kty: %q", kty)
	}
}

// ecJWKToPublicKeyAssertion converts an EC JWK (P-256 / P-384) to
// an ecdsa.PublicKey, rejecting P-521 and other curves. On-curve
// validation uses crypto/ecdh; coordinates are left-padded to the
// expected field-element length.
func ecJWKToPublicKeyAssertion(crv string, xBytes, yBytes []byte) (*ecdsa.PublicKey, error) {
	type ecCurve struct {
		curve     elliptic.Curve
		coordLen  int
		newECDHFn func([]byte) (*ecdh.PublicKey, error)
	}
	var ec ecCurve
	switch crv {
	case "P-256":
		ec = ecCurve{elliptic.P256(), 32, ecdh.P256().NewPublicKey}
	case "P-384":
		ec = ecCurve{elliptic.P384(), 48, ecdh.P384().NewPublicKey}
	default:
		return nil, fmt.Errorf("EC key with unsupported crv: %q (P-256 and P-384 supported)", crv)
	}
	if len(xBytes) > ec.coordLen || len(yBytes) > ec.coordLen {
		return nil, fmt.Errorf("EC/%s coord too long: x=%d y=%d", crv, len(xBytes), len(yBytes))
	}
	xPadded := make([]byte, ec.coordLen)
	yPadded := make([]byte, ec.coordLen)
	copy(xPadded[ec.coordLen-len(xBytes):], xBytes)
	copy(yPadded[ec.coordLen-len(yBytes):], yBytes)
	uncompressed := append(append([]byte{0x04}, xPadded...), yPadded...)
	if _, err := ec.newECDHFn(uncompressed); err != nil {
		return nil, fmt.Errorf("EC/%s key: %w", crv, err)
	}
	return &ecdsa.PublicKey{
		Curve: ec.curve,
		X:     new(big.Int).SetBytes(xPadded),
		Y:     new(big.Int).SetBytes(yPadded),
	}, nil
}

// extractAssertionAudience reads the standard `aud` claim,
// accepting either a JSON string or an array of strings per
// RFC 7519 §4.1.3.
func extractAssertionAudience(claims jwt.MapClaims) ([]string, error) {
	raw, ok := claims["aud"]
	if !ok {
		return nil, errors.New("assertion missing aud claim")
	}
	switch v := raw.(type) {
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("aud array contains non-string entry: %T", item)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, errors.New("aud array is empty")
		}
		return out, nil
	default:
		return nil, fmt.Errorf("aud claim has unexpected type %T", raw)
	}
}

// extractAssertionTime reads a numeric-date claim per RFC 7519.
func extractAssertionTime(claims jwt.MapClaims, name string, required bool) (*time.Time, error) {
	raw, ok := claims[name]
	if !ok {
		if required {
			return nil, fmt.Errorf("assertion missing required %s claim", name)
		}
		return nil, nil
	}
	switch v := raw.(type) {
	case float64:
		t := time.Unix(int64(v), 0).UTC()
		return &t, nil
	case int64:
		t := time.Unix(v, 0).UTC()
		return &t, nil
	case int:
		t := time.Unix(int64(v), 0).UTC()
		return &t, nil
	default:
		return nil, fmt.Errorf("%s claim has unexpected type %T", name, raw)
	}
}

func assertionAudienceContains(tokenAud []string, tokenEndpointURL string) bool {
	for _, a := range tokenAud {
		if a == tokenEndpointURL {
			return true
		}
	}
	return false
}
