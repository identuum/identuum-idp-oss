package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
)

// ============================================================================
// Token Validation (Replaces symmetric ValidateJWTToken)
// ============================================================================

// standardKeyFunc encapsulates the strict algorithm enforcement logic.
// It verifies that the token's signing method exactly matches the registered
// KeyAlgorithm, explicitly rejecting symmetric substitution attacks or unsupported algorithms.
func (km *KeyManager) standardKeyFunc(token *jwt.Token) (any, error) {
	kidInterface, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}
	kid, ok := kidInterface.(string)
	if !ok {
		return nil, fmt.Errorf("invalid kid type in token header")
	}

	// Lookup key by kid
	km.mu.RLock()
	key, exists := km.keys[kid]
	km.mu.RUnlock()

	if !exists {
		logger.Warning.WithFields(map[string]any{
			"kid": kid,
		}).Print("Unknown key ID in token validation")
		return nil, fmt.Errorf("unknown key ID: %s", kid)
	}

	// Verify algorithm matches key type (prevent algorithm substitution attacks).
	// RS256 is verify-only per docs/ID_JAG_DESIGN.md cross-Q finding #15:
	// loaded RS256 keys (Algorithm=RS256, PrivateKey empty by parseKey
	// invariant) match incoming jwt.SigningMethodRSA tokens during
	// verification. The signing path (SignBytes / GenerateJWTToken / etc.)
	// continues to refuse RS256 via its own default-case rejection.
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("token algorithm mismatch: expected EdDSA, got %v", token.Header["alg"])
		}
	case domain.KeyAlgorithmES256:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("token algorithm mismatch: expected ES256, got %v", token.Header["alg"])
		}
	case domain.KeyAlgorithmRS256:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token algorithm mismatch: expected RS256, got %v", token.Header["alg"])
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm or attempted substitution: %s", key.Algorithm)
	}

	logger.Debug.WithFields(map[string]any{
		"kid":       kid,
		"algorithm": key.Algorithm,
	}).Print("Validating token with key")

	// Return public key for signature verification
	return key.PublicKey, nil
}

// ValidateJWTToken validates a JWT token using any active/rotating key
//
// Validation process:
// 1. Extract kid from token header
// 2. Lookup key by kid in key manager
// 3. Verify algorithm matches expected type
// 4. Validate signature with public key
func (km *KeyManager) ValidateJWTToken(tokenString string) (*domain.JWTClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("%s", ErrMsgInvalidTokenFormat)
	}

	// Basic format validation (3 parts: header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%s", ErrMsgInvalidTokenFormat)
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&privateJWTClaims{},
		km.standardKeyFunc,
	)

	if err != nil {
		// Preserve original error messages for compatibility
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%s", ErrMsgTokenExpired)
		}
		return nil, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	privateClaims, ok := token.Claims.(*privateJWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	// §7 structural-claim invariants. exp/nbf are enforced by jwt/v5 via token.Valid above.
	// iss is intentionally NOT asserted here because the structural validator does not know
	// the expected issuer; use sites verify iss against their configured value (e.g.,
	// JWTTokenService.VerifyIDToken checks iss before delegating). jti is N/A: refresh
	// tokens are opaque SecureToken-encoded strings, not JWTs, so the §7 "jti (refresh)
	// required" clause has no surface in this validator.
	if privateClaims.Subject == "" {
		return nil, fmt.Errorf("%s", ErrMsgInvalidToken)
	}
	if len(privateClaims.Audience) == 0 {
		return nil, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	claims := &domain.JWTClaims{
		UserID:         privateClaims.UserID,
		Email:          privateClaims.Email,
		OrganizationID: privateClaims.OrganizationID,
		Role:           privateClaims.Role,
		SessionID:      privateClaims.SessionID,
		Type:           privateClaims.Type,
		Kind:           privateClaims.Kind,
		Scope:          privateClaims.Scope,
		ClientID:       privateClaims.ClientID,
		Issuer:         privateClaims.Issuer,
		Subject:        privateClaims.Subject,
		Audience:       privateClaims.Audience,
		ID:             privateClaims.ID,
		Purpose:        privateClaims.Purpose,
		Acr:            privateClaims.Acr,
		AuthTime:       privateClaims.AuthTime,
	}

	if privateClaims.ExpiresAt != nil {
		claims.ExpiresAt = privateClaims.ExpiresAt.Time
	}
	if privateClaims.NotBefore != nil {
		claims.NotBefore = &privateClaims.NotBefore.Time
	}
	if privateClaims.IssuedAt != nil {
		claims.IssuedAt = privateClaims.IssuedAt.Time
	}

	return claims, nil
}

// ValidateJWTTokenAllowExpired is a narrow variant of ValidateJWTToken that
// validates the JWS signature and structural claim shape but tolerates an
// expired `exp`. It is intended for handlers that need to distinguish a
// structurally valid but time-expired token from an invalid one — for
// example, to return a differentiated "capability window closed" response
// rather than a generic 401.
//
// Returns (claims, expired, err):
//
//   - err non-nil           → token is unusable (signature invalid, malformed,
//     etc.). Caller MUST reject with 401. `claims` and `expired` are zero.
//   - err nil, expired=true → signature valid but `exp` past. Caller may
//     proceed with reduced authority when the caller's protocol explicitly
//     requires distinguishing expiry from invalidity.
//   - err nil, expired=false → fully valid token; equivalent to ValidateJWTToken.
//
// SECURITY NOTE: every other use site in the codebase MUST keep using
// ValidateJWTToken. Granting an expired token any authority is the inverse
// of what JWT exp is for; use this helper only when the calling protocol
// explicitly requires surfacing the expiry state as a distinct response.
func (km *KeyManager) ValidateJWTTokenAllowExpired(tokenString string) (claims *domain.JWTClaims, expired bool, err error) {
	if tokenString == "" {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidTokenFormat)
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidTokenFormat)
	}

	// Parse with exp validation disabled so an expired-but-otherwise-valid
	// token still produces parsed claims. Other structural checks (signature,
	// nbf, claim presence) remain enforced exactly as ValidateJWTToken would.
	parser := jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithoutClaimsValidation())
	token, parseErr := parser.ParseWithClaims(tokenString, &privateJWTClaims{}, km.standardKeyFunc)
	if parseErr != nil {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}
	if !token.Valid {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	privateClaims, ok := token.Claims.(*privateJWTClaims)
	if !ok {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	// Re-apply the structural checks that ValidateJWTToken enforces post-Valid.
	if privateClaims.Subject == "" {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}
	if len(privateClaims.Audience) == 0 {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}
	// nbf (when present) is a hard gate — a not-yet-valid token is rejected
	// regardless of token_use because there is no use case for a pre-active
	// capability.
	now := time.Now()
	if privateClaims.NotBefore != nil && now.Before(privateClaims.NotBefore.Time) {
		return nil, false, fmt.Errorf("%s", ErrMsgInvalidToken)
	}

	expired = privateClaims.ExpiresAt != nil && now.After(privateClaims.ExpiresAt.Time)

	out := &domain.JWTClaims{
		UserID:         privateClaims.UserID,
		Email:          privateClaims.Email,
		OrganizationID: privateClaims.OrganizationID,
		Role:           privateClaims.Role,
		SessionID:      privateClaims.SessionID,
		Type:           privateClaims.Type,
		Kind:           privateClaims.Kind,
		Scope:          privateClaims.Scope,
		ClientID:       privateClaims.ClientID,
		Issuer:         privateClaims.Issuer,
		Subject:        privateClaims.Subject,
		Audience:       privateClaims.Audience,
		ID:             privateClaims.ID,
		Purpose:        privateClaims.Purpose,
		Acr:            privateClaims.Acr,
		AuthTime:       privateClaims.AuthTime,
	}
	if privateClaims.ExpiresAt != nil {
		out.ExpiresAt = privateClaims.ExpiresAt.Time
	}
	if privateClaims.NotBefore != nil {
		out.NotBefore = &privateClaims.NotBefore.Time
	}
	if privateClaims.IssuedAt != nil {
		out.IssuedAt = privateClaims.IssuedAt.Time
	}
	return out, expired, nil
}
