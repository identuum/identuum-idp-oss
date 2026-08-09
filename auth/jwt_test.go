package auth

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
)

func init() {
	logger.InitializeZapLogger()
}

func generateTestEdDSAKey() domain.SigningKey {
	key, _ := GenerateEdDSAKey()
	return *key
}

func generateTestES256Key() domain.SigningKey {
	key, _ := GenerateES256Key()
	return *key
}

func TestNewKeyManager(t *testing.T) {
	t.Run("empty_keys", func(t *testing.T) {
		km, err := NewKeyManager([]domain.SigningKey{})
		assert.Error(t, err)
		assert.Nil(t, km)
	})

	t.Run("success_eddsa_primary", func(t *testing.T) {
		k1 := generateTestEdDSAKey()
		km, err := NewKeyManager([]domain.SigningKey{k1})
		assert.NoError(t, err)
		assert.NotNil(t, km)
		assert.Equal(t, k1.KID, km.primaryKey.KID)
		assert.IsType(t, ed25519.PrivateKey{}, km.primaryKey.PrivateKey)
	})

	t.Run("success_es256_primary", func(t *testing.T) {
		k1 := generateTestES256Key()
		km, err := NewKeyManager([]domain.SigningKey{k1})
		assert.NoError(t, err)
		assert.NotNil(t, km)
		assert.Equal(t, k1.KID, km.primaryKey.KID)
	})

	t.Run("preference_eddsa_over_es256", func(t *testing.T) {
		k1 := generateTestES256Key()
		k2 := generateTestEdDSAKey()
		km, err := NewKeyManager([]domain.SigningKey{k1, k2})
		assert.NoError(t, err)
		assert.NotNil(t, km)
		// Should prefer EdDSA as primary
		assert.Equal(t, k2.KID, km.primaryKey.KID)
	})

	t.Run("invalid_key", func(t *testing.T) {
		k1 := domain.SigningKey{
			KID:        "invalid",
			Algorithm:  domain.KeyAlgorithmEdDSA,
			State:      domain.KeyStateActive,
			PrivateKey: "not-a-pem",
		}
		km, err := NewKeyManager([]domain.SigningKey{k1})
		assert.Error(t, err)
		assert.Nil(t, km)
	})
}

func TestKeyManager_GenerateAndValidateJWTToken(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	orgID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())

	opts := GenerateTokenOptions{
		UserID:    userID,
		OrgID:     orgID,
		SessionID: sessionID,
		Email:     "test@example.com",
		Role:      domain.RoleOrgAdmin,
		ExpiresIn: time.Hour,
		Audience:  "test-aud",
		Scope:     "read:all",
	}

	tokenString, err := km.GenerateJWTToken(opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Validate it
	claims, err := km.ValidateJWTToken(tokenString)
	assert.NoError(t, err)
	assert.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, orgID, claims.OrganizationID)
	assert.Equal(t, string(domain.RoleOrgAdmin), claims.Role)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Contains(t, claims.Audience, "test-aud")
	assert.Equal(t, "read:all", claims.Scope)

	// Check manual expiration by parsing
	parsed, _ := jwt.Parse(tokenString, km.standardKeyFunc)
	assert.True(t, parsed.Valid)
}

func TestKeyManager_ExpiredToken(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	opts := GenerateTokenOptions{
		UserID:    uuid.Must(uuid.NewV7()),
		ExpiresIn: -1 * time.Hour, // Create already expired token
	}

	tokenString, _ := km.GenerateJWTToken(opts)
	claims, err := km.ValidateJWTToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Equal(t, ErrMsgTokenExpired, err.Error())
}

func TestKeyManager_IdentifyAlgorithmChangeAttack(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	// Create a token that appears to be valid but claims wrong algorithm (e.g. HS256 algorithm substitution attack)
	// We'll mimic parsing returning an error
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii" + key.KID + "In0.e30.signature"

	claims, err := km.ValidateJWTToken(invalidToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestKeyManager_GenerateIDToken(t *testing.T) {
	key := generateTestES256Key()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	claims := domain.OIDCIDTokenClaims{
		Issuer:    "https://auth.example.com",
		Subject:   "user123",
		Audience:  []string{"client_app"},
		ExpiresAt: time.Now().Add(time.Hour),
		IssuedAt:  time.Now(),
		AuthTime:  time.Now().Unix(),
		Nonce:     "randomnonce",
		Email:     "user@example.com",
		Role:      "user",
	}

	token, err := km.GenerateIDToken(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Can we parse it back?
	parsed, err := jwt.Parse(token, km.standardKeyFunc)
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	mapClaims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "user@example.com", mapClaims["email"])
	assert.Equal(t, "randomnonce", mapClaims["nonce"])
}

func TestKeyManager_VerificationToken(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	email := "verify@example.com"
	issuer := "https://auth.example.com"

	token, err := km.GenerateVerificationToken(userID, email, issuer)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	retID, retEmail, err := km.ValidateVerificationToken(token, issuer)
	assert.NoError(t, err)
	assert.Equal(t, userID, retID)
	assert.Equal(t, email, retEmail)
}

func TestKeyManager_Reload(t *testing.T) {
	k1 := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{k1})
	assert.Equal(t, k1.KID, km.primaryKey.KID)

	k2 := generateTestEdDSAKey()
	err := km.Reload([]domain.SigningKey{k2})
	assert.NoError(t, err)

	assert.Equal(t, k2.KID, km.primaryKey.KID)
}

func TestKeyManager_SignAccessToken(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	claims := domain.JWTClaims{
		UserID:   uuid.Must(uuid.NewV7()),
		Issuer:   "identuum",
		Audience: []string{"api"},
	}

	token, err := km.SignAccessToken(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestValidateVerificationToken_WrongAudience(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	email := "wrong-aud@example.com"
	issuer := "https://auth.example.com"

	// Generate a legitimate verification token first to confirm round-trip works.
	validToken, err := km.GenerateVerificationToken(userID, email, issuer)
	assert.NoError(t, err)
	retID, retEmail, err := km.ValidateVerificationToken(validToken, issuer)
	assert.NoError(t, err)
	assert.Equal(t, userID, retID)
	assert.Equal(t, email, retEmail)

	// Now craft a token with the wrong audience ("identuum-admin") using the same key.
	// This simulates a token forged from a different token purpose being replayed.
	wrongAudToken, err := km.GenerateJWTToken(GenerateTokenOptions{
		UserID:    userID,
		ExpiresIn: time.Hour,
		Audience:  "identuum-admin",
	})
	assert.NoError(t, err)

	// ValidateVerificationToken must reject a token with audience != "verify-email".
	_, _, err = km.ValidateVerificationToken(wrongAudToken, issuer)
	assert.Error(t, err, "ValidateVerificationToken must reject tokens with wrong audience")
}

func TestKeyManager_VerificationToken_IssuerMismatch(t *testing.T) {
	key := generateTestEdDSAKey()
	km, _ := NewKeyManager([]domain.SigningKey{key})

	userID := uuid.Must(uuid.NewV7())
	email := "issuer-test@example.com"
	issuer := "https://auth.example.com"

	token, err := km.GenerateVerificationToken(userID, email, issuer)
	assert.NoError(t, err)

	// Must be rejected when validating against a different deployment URL.
	_, _, err = km.ValidateVerificationToken(token, "https://evil.example.com")
	assert.Error(t, err, "ValidateVerificationToken must reject tokens with wrong issuer")
	assert.Contains(t, err.Error(), "invalid token issuer")

	// Must succeed with the correct issuer.
	retID, retEmail, err := km.ValidateVerificationToken(token, issuer)
	assert.NoError(t, err)
	assert.Equal(t, userID, retID)
	assert.Equal(t, email, retEmail)
}

// TestKeyManager_ValidateJWTToken_IgnoresUnknownClaims verifies that the implementation
// strictly ignores unrecognized JWT claims (e.g. "future_claim") during parsing,
// adhering to the forward-compatibility guarantee specified in Section 8.13.
func TestKeyManager_ValidateJWTToken_IgnoresUnknownClaims(t *testing.T) {
	key := generateTestEdDSAKey()
	km, err := NewKeyManager([]domain.SigningKey{key})
	assert.NoError(t, err)

	// Create a token with an unrecognized claim
	mapClaims := jwt.MapClaims{
		"exp":          jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		"iat":          jwt.NewNumericDate(time.Now()),
		"sub":          uuid.Must(uuid.NewV7()).String(),
		"iss":          "https://auth.example.com",
		"aud":          []string{"https://api.example.com"},
		"future_claim": "unrecognized", // This is the unknown claim
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, mapClaims)
	token.Header["kid"] = key.KID
	tokenString, err := token.SignedString(km.primaryKey.PrivateKey)
	assert.NoError(t, err, "failed to sign manual token")

	// Validate the token through the KeyManager
	claims, err := km.ValidateJWTToken(tokenString)
	assert.NoError(t, err, "ValidateJWTToken should ignore unrecognized claims and succeed")
	assert.NotNil(t, claims)
	assert.Equal(t, "https://auth.example.com", claims.Issuer)
}
