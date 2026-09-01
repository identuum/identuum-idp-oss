package service

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// jwtIDTokenIssuer is the OSS JWT implementation of oidc.IDTokenIssuer (A-4
// Phase 4). The DEFAULT signing posture is the pre-A-4 inline one verbatim —
// selectUserSigningKey (EdDSA-preferred / ES256-fallback, never RS256) +
// parsePrivateKeyPEM + jwt.NewWithClaims + SignedString — so default-path
// tokens are byte-identical to the pre-A-4 path. THE-PKCE-DECISION adds one
// escape hatch: when the client explicitly registered
// id_token_signed_response_alg, selectIDTokenSigningKey honors that exact
// algorithm (including RS256, testing-only, never default).
// It lives in `internal/` because it needs the SigningKeyProvider seam,
// domain.SigningKey, and the internal key-parsing helper.
//
// The sign step is duplicated from jwtAccessTokenMinter rather than shared:
// the two mint paths surface DISTINCT error sentinels (ErrIDToken* vs
// ErrTokenService*), which OSS keeps auditable per service, so a shared
// helper would only re-introduce a mapping layer.
type jwtIDTokenIssuer struct {
	keys SigningKeyProvider
}

// newJWTIDTokenIssuer constructs the JWT ID-token issuer over a signing-key
// provider. keys must be non-nil (the constructing service enforces this).
func newJWTIDTokenIssuer(keys SigningKeyProvider) *jwtIDTokenIssuer {
	return &jwtIDTokenIssuer{keys: keys}
}

// IssueIDToken signs a compact OIDC ID token for the supplied claims. It
// reproduces the pre-A-4 inline mapping exactly:
//
//   - iss/sub/aud/iat/exp/jti are always present.
//   - nonce is emitted only when non-empty.
//   - every Extra entry is copied verbatim (auth_time, acr, amr, email,
//     email_verified, ...).
//
// The header carries alg (from the selected key's method) + kid. Errors
// mirror the previous inline path: ErrIDTokenNoSigningKey when no active key
// satisfies the selection (default EdDSA/ES256 order, or the client's
// explicit SigningAlg), ErrIDTokenSigningFailed on a key-parse or signing
// failure.
func (i *jwtIDTokenIssuer) IssueIDToken(ctx context.Context, tc oidc.IDTokenClaims) (string, error) {
	signingKey, method, err := selectIDTokenSigningKey(ctx, i.keys, tc.SigningAlg)
	if err != nil {
		return "", ErrIDTokenNoSigningKey
	}
	priv, err := parsePrivateKeyPEM(signingKey.PrivateKey, signingKey.Algorithm)
	if err != nil {
		return "", ErrIDTokenSigningFailed
	}
	claims := jwt.MapClaims{
		"iss": tc.Issuer,
		"sub": tc.Subject,
		"aud": tc.Audience,
		"iat": tc.IssuedAt.Unix(),
		"exp": tc.ExpiresAt.Unix(),
		"jti": tc.JTI,
	}
	if tc.Nonce != "" {
		claims["nonce"] = tc.Nonce
	}
	for k, v := range tc.Extra {
		claims[k] = v
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = signingKey.KID
	signed, err := token.SignedString(priv)
	if err != nil {
		return "", ErrIDTokenSigningFailed
	}
	return signed, nil
}

// selectIDTokenSigningKey resolves the signing key for an ID token.
//
// alg is the client's explicitly registered id_token_signed_response_alg
// ("EdDSA", "ES256", "RS256") or empty for "issuer default".
//
// THE-PKCE-DECISION (owner ruling): the DEFAULT path is exactly
// selectUserSigningKey — EdDSA preferred, ES256 fallback, RS256 NEVER.
// An RS256 key, even when present and active, signs ONLY when the
// client explicitly registered RS256; that capability exists for
// conformance/interop testing, not operation (docs/TESTING-OPERATORS.md).
func selectIDTokenSigningKey(ctx context.Context, keys SigningKeyProvider, alg string) (*domain.SigningKey, jwt.SigningMethod, error) {
	// "" and "EdDSA" are BOTH the issuer default order (EdDSA-preferred /
	// ES256-fallback): EdDSA *is* the default, and every pre-existing row
	// reads back the migration's 'EdDSA' column default — a strict match
	// here would break deployments whose only active key is ES256, which
	// the pre-THE-PKCE-DECISION path served via the fallback. ES256 and
	// RS256 are explicit deviations and match strictly.
	if alg == "" || alg == string(domain.KeyAlgorithmEdDSA) {
		return selectUserSigningKey(ctx, keys)
	}
	var want domain.KeyAlgorithm
	var method jwt.SigningMethod
	switch alg {
	case string(domain.KeyAlgorithmES256):
		want, method = domain.KeyAlgorithmES256, jwt.SigningMethodES256
	case string(domain.KeyAlgorithmRS256):
		want, method = domain.KeyAlgorithmRS256, jwt.SigningMethodRS256
	default:
		return nil, nil, ErrTokenServiceNoSigningKey
	}
	if keys == nil {
		return nil, nil, ErrTokenServiceNoSigningKey
	}
	out, err := keys.ListActive(ctx)
	if err != nil {
		return nil, nil, ErrTokenServiceNoSigningKey
	}
	for i := range out {
		k := &out[i]
		if k.Algorithm == want && k.PrivateKey != "" {
			return k, method, nil
		}
	}
	return nil, nil, ErrTokenServiceNoSigningKey
}

// Compile-time proof the JWT issuer satisfies the format-neutral seam.
var _ oidc.IDTokenIssuer = (*jwtIDTokenIssuer)(nil)
