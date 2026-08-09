package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomString(t *testing.T) {
	str, err := GenerateRandomString(16)
	require.NoError(t, err)

	// Since it's hex encoded, 16 bytes = 32 chars
	assert.Len(t, str, 32)

	// Test it's valid hex
	_, err = hex.DecodeString(str)
	assert.NoError(t, err)

	// Test uniqueness
	str2, err := GenerateRandomString(16)
	require.NoError(t, err)
	assert.NotEqual(t, str, str2)

	// Test 0 bytes
	str0, err := GenerateRandomString(0)
	require.NoError(t, err)
	assert.Empty(t, str0)
}

func TestHashToken(t *testing.T) {
	token := "my-secret-token"
	hash := HashToken(token)

	// SHA256 is 32 bytes, hex encoded is 64 chars
	assert.Len(t, hash, 64)

	// Should be deterministic
	hash2 := HashToken(token)
	assert.Equal(t, hash, hash2)

	// Different input should give different hash
	hash3 := HashToken("different-token")
	assert.NotEqual(t, hash, hash3)
}

func TestHashSecret(t *testing.T) {
	secret := "my-app-secret"
	hash := HashSecret(secret)

	// Functionally identical to HashToken
	assert.Len(t, hash, 64)
	assert.Equal(t, HashSecret(secret), hash)

	hash2 := HashSecret("different-secret")
	assert.NotEqual(t, hash, hash2)
}
