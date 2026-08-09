package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateRandomString generates a random hex string from the specified number of random bytes.
// The resulting string length will be 2 * bytes.
func GenerateRandomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken computes a SHA256 hash of the token (e.g., password reset token).
// It returns the hex-encoded string of the hash.
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashSecret computes a SHA256 hash of the secret (e.g., client secret).
// It returns the hex-encoded string of the hash.
// This is functionally identical to HashToken but named for semantic clarity.
func HashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}
