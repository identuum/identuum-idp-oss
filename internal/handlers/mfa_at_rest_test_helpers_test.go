package handlers

import "github.com/identuum/identuum-idp-oss/internal/crypto"

// identityMFACipher is a handlers-package test double for
// service.MFASecretCipher: it round-trips a seed unchanged so the existing
// MFA handler tests (which set/assert a plaintext MFASecret) keep passing
// without per-test ciphertext bookkeeping. Real AES-256-GCM encryption is
// proven in the service package's at-rest tests.
type identityMFACipher struct{}

func (identityMFACipher) Encrypt(plaintext string) (string, error)  { return plaintext, nil }
func (identityMFACipher) Decrypt(ciphertext string) (string, error) { return ciphertext, nil }

// hashCodesForTest mirrors the service's at-rest recovery-code hashing so a
// handler test that seeds a user's recovery-code column stores the same
// SHA-256 hashes the consume path matches against.
func hashCodesForTest(plain []string) []string {
	out := make([]string, len(plain))
	for i, c := range plain {
		out[i] = crypto.HashSecret(c)
	}
	return out
}
