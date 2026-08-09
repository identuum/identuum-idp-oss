package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
)

// ============================================================================
// Token Generation (Replaces symmetric GenerateJWTToken)
// ============================================================================

// GenerateTokenOptions contains parameters for token generation
type GenerateTokenOptions struct {
	UserID    uuid.UUID
	OrgID     uuid.UUID
	SessionID uuid.UUID
	Email     string
	Role      domain.UserRole
	ExpiresIn time.Duration
	Audience  string
	Scope     string
	// Acr and AuthTime stamp the access token's authentication context
	// for downstream ACR floor enforcement on step-up flows. Both
	// derived from the underlying domain.Session via EffectiveACR /
	// EffectiveAuthTime so step-ups are honoured. Zero values are
	// permitted on paths with no session context (M2M tokens) — the
	// resulting claims are simply omitted.
	Acr      string
	AuthTime time.Time
}

// GenerateJWTToken creates a new JWT token signed with the primary key
func (km *KeyManager) GenerateJWTToken(opts GenerateTokenOptions) (string, error) {
	km.mu.RLock()
	key := km.primaryKey
	km.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("no active signing key available")
	}

	aud := "identuum-admin"
	if opts.Audience != "" {
		aud = opts.Audience
	}

	now := time.Now()
	var authTimeUnix int64
	if !opts.AuthTime.IsZero() {
		authTimeUnix = opts.AuthTime.Unix()
	}
	claims := privateJWTClaims{
		UserID:         opts.UserID,
		Email:          opts.Email,
		OrganizationID: opts.OrgID,
		Role:           string(opts.Role),
		SessionID:      opts.SessionID,
		Scope:          opts.Scope,
		Acr:            opts.Acr,
		AuthTime:       authTimeUnix,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(opts.ExpiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   opts.UserID.String(),
			Audience:  jwt.ClaimStrings{aud},
		},
	}

	// Select signing method based on algorithm
	var token *jwt.Token
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	case domain.KeyAlgorithmES256:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}

	// Add key ID to header for JWKS lookup (NEW - critical for key rotation)
	token.Header["kid"] = key.KID

	// Sign with private key
	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	logger.Debug.WithFields(map[string]any{
		"kid":       key.KID,
		"algorithm": key.Algorithm,
		"user_id":   opts.UserID,
	}).Print("Generated JWT token")

	return signedToken, nil
}

// GenerateIDToken creates a specific OIDC ID Token
func (km *KeyManager) GenerateIDToken(claims domain.OIDCIDTokenClaims) (string, error) {
	km.mu.RLock()
	key := km.primaryKey
	km.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("no active signing key available")
	}

	internalClaims := privateOIDCIDTokenClaims{
		AuthTime:  claims.AuthTime,
		Nonce:     claims.Nonce,
		Email:     claims.Email,
		Groups:    claims.Groups,
		Name:      claims.Name,
		Role:      claims.Role,
		SessionID: claims.SessionID,
		Acr:       claims.Acr,
		Amr:       claims.Amr,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  claims.Audience,
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			ID:        claims.ID,
		},
	}
	if claims.NotBefore != nil {
		internalClaims.NotBefore = jwt.NewNumericDate(*claims.NotBefore)
	}

	// Select signing method based on algorithm
	var token *jwt.Token
	switch key.Algorithm {
	case domain.KeyAlgorithmEdDSA:
		token = jwt.NewWithClaims(jwt.SigningMethodEdDSA, internalClaims)
	case domain.KeyAlgorithmES256:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, internalClaims)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
	}

	// Add key ID to header
	token.Header["kid"] = key.KID

	// Sign with private key
	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return signedToken, nil
}
