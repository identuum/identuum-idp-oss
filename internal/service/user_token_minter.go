package service

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// jwtAccessTokenMinter is the OSS JWT implementation of
// oidc.AccessTokenMinter (A-4 Phase 1). It wraps the existing OSS signing
// posture verbatim — selectUserSigningKey (EdDSA-preferred / ES256-fallback
// / RS256-banned) + parsePrivateKeyPEM + jwt.NewWithClaims + SignedString —
// so rewiring a flow through this minter produces byte-identical tokens. It
// lives in `internal/` (not the OSS pkg/oidc leaf) because it needs the
// SigningKeyProvider seam, domain.SigningKey, and the internal key-parsing
// helpers.
type jwtAccessTokenMinter struct {
	keys SigningKeyProvider
}

// newJWTAccessTokenMinter constructs the JWT minter over a signing-key
// provider. keys must be non-nil (the constructing service already enforces
// this); a nil provider surfaces as ErrTokenServiceNoSigningKey at Mint.
func newJWTAccessTokenMinter(keys SigningKeyProvider) *jwtAccessTokenMinter {
	return &jwtAccessTokenMinter{keys: keys}
}

// Mint signs a compact JWT for the supplied claims and returns
// (compactJWT, jti). It reproduces the pre-A-4 inline mapping exactly:
//
//   - iss/sub/aud/iat/exp/jti are always present.
//   - actor_type/client_id/scope are emitted only when non-empty (a
//     user token leaves client_id/scope empty, so no such claims appear).
//   - every Extra entry is copied verbatim (org_id, email, role,
//     session_id, auth_time, acr, amr, ...).
//
// The header carries alg (from the selected key's method) + kid. storeKey is
// the jti. Errors mirror the previous inline path: ErrTokenServiceNoSigningKey
// when no EdDSA/ES256 active key exists, ErrTokenServiceSigningFailed on a
// key-parse or signing failure.
func (m *jwtAccessTokenMinter) Mint(ctx context.Context, tc oidc.TokenClaims) (string, string, error) {
	signingKey, method, err := selectUserSigningKey(ctx, m.keys)
	if err != nil {
		return "", "", err
	}
	priv, err := parsePrivateKeyPEM(signingKey.PrivateKey, signingKey.Algorithm)
	if err != nil {
		return "", "", ErrTokenServiceSigningFailed
	}
	claims := jwt.MapClaims{
		"iss": tc.Issuer,
		"sub": tc.Subject,
		"aud": tc.Audience,
		"iat": tc.IssuedAt.Unix(),
		"exp": tc.ExpiresAt.Unix(),
		"jti": tc.JTI,
	}
	if tc.ActorType != "" {
		claims["actor_type"] = tc.ActorType
	}
	if tc.ClientID != "" {
		claims["client_id"] = tc.ClientID
	}
	if tc.Scope != "" {
		claims["scope"] = tc.Scope
	}
	for k, v := range tc.Extra {
		claims[k] = v
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = signingKey.KID
	signed, err := token.SignedString(priv)
	if err != nil {
		return "", "", ErrTokenServiceSigningFailed
	}
	return signed, tc.JTI, nil
}

// Compile-time proof the JWT minter satisfies the format-neutral seam.
var _ oidc.AccessTokenMinter = (*jwtAccessTokenMinter)(nil)
