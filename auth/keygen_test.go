package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/pem"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/logger"
	"github.com/stretchr/testify/assert"
)

func init() {
	logger.InitializeZapLogger()
}

func TestGenerateEdDSAKey(t *testing.T) {
	key, err := GenerateEdDSAKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)

	assert.Equal(t, domain.KeyAlgorithmEdDSA, key.Algorithm)
	assert.Equal(t, domain.KeyStateActive, key.State)
	assert.Contains(t, key.KID, "eddsa-")
	assert.Nil(t, key.CreatedBy)

	// Validate PEM formats
	privBlock, _ := pem.Decode([]byte(key.PrivateKey))
	assert.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	pubBlock, _ := pem.Decode([]byte(key.PublicKey))
	assert.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	// Verify we can parse it
	parsed, err := parseKey(*key)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.IsType(t, ed25519.PrivateKey{}, parsed.PrivateKey)
}

func TestGenerateES256Key(t *testing.T) {
	key, err := GenerateES256Key()
	assert.NoError(t, err)
	assert.NotNil(t, key)

	assert.Equal(t, domain.KeyAlgorithmES256, key.Algorithm)
	assert.Equal(t, domain.KeyStateActive, key.State)
	assert.Contains(t, key.KID, "es256-")
	assert.Nil(t, key.CreatedBy)

	// Validate PEM formats
	privBlock, _ := pem.Decode([]byte(key.PrivateKey))
	assert.NotNil(t, privBlock)
	assert.Equal(t, "PRIVATE KEY", privBlock.Type)

	pubBlock, _ := pem.Decode([]byte(key.PublicKey))
	assert.NotNil(t, pubBlock)
	assert.Equal(t, "PUBLIC KEY", pubBlock.Type)

	// Verify we can parse it
	parsed, err := parseKey(*key)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.IsType(t, &ecdsa.PrivateKey{}, parsed.PrivateKey)
}

func TestAutoGenerateInitialKey(t *testing.T) {
	t.Run("Generate_EdDSA", func(t *testing.T) {
		key, err := AutoGenerateInitialKey(string(domain.KeyAlgorithmEdDSA))
		assert.NoError(t, err)
		assert.Equal(t, domain.KeyAlgorithmEdDSA, key.Algorithm)
	})

	t.Run("Generate_ES256", func(t *testing.T) {
		key, err := AutoGenerateInitialKey(string(domain.KeyAlgorithmES256))
		assert.NoError(t, err)
		assert.Equal(t, domain.KeyAlgorithmES256, key.Algorithm)
	})

	t.Run("Generate_DefaultFallback", func(t *testing.T) {
		// Should default to EdDSA for invalid algorithm
		key, err := AutoGenerateInitialKey("INVALID_ALGO")
		assert.NoError(t, err)
		assert.Equal(t, domain.KeyAlgorithmEdDSA, key.Algorithm)
	})
}
