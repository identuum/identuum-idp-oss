package service

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// jwtIDTokenIssuer is the OSS JWT implementation of oidc.IDTokenIssuer (A-4
// Phase 4). It reproduces the pre-A-4 inline id-token signing posture
// verbatim — selectUserSigningKey (EdDSA-preferred / ES256-fallback /
// RS256-banned) + parsePrivateKeyPEM + jwt.NewWithClaims + SignedString — so
// rewiring IDTokenService.Issue through it produces byte-identical tokens.
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
// mirror the previous inline path: ErrIDTokenNoSigningKey when no EdDSA/ES256
// active key exists, ErrIDTokenSigningFailed on a key-parse or signing failure.
func (i *jwtIDTokenIssuer) IssueIDToken(ctx context.Context, tc oidc.IDTokenClaims) (string, error) {
	signingKey, method, err := selectUserSigningKey(ctx, i.keys)
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

// Compile-time proof the JWT issuer satisfies the format-neutral seam.
var _ oidc.IDTokenIssuer = (*jwtIDTokenIssuer)(nil)
