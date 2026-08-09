package crypto

import (
	"strings"
	"testing"
)

func TestGenerateHash(t *testing.T) {
	password := []byte("super_secure_password_123")

	hash, err := GenerateHash(password)
	if err != nil {
		t.Fatalf("failed to generate hash: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("unexpected hash prefix, got %s", hash)
	}

	// Ensure the hash contains 6 parts (split by $)
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 parts in PHC string, got %d", len(parts))
	}
}

func TestCompareHashAndPassword_Argon2(t *testing.T) {
	password := []byte("correct_horse_battery_staple")
	hash, err := GenerateHash(password)
	if err != nil {
		t.Fatalf("failed to generate hash: %v", err)
	}

	// Valid comparison
	if err := CompareHashAndPassword([]byte(hash), password); err != nil {
		t.Errorf("CompareHashAndPassword returned unexpected error: %v", err)
	}

	// Invalid password
	if err := CompareHashAndPassword([]byte(hash), []byte("wrong_password")); err != ErrMismatchedHashAndPassword {
		t.Errorf("expected ErrMismatchedHashAndPassword, got %v", err)
	}
}

func TestCompareHashAndPassword_NonArgon2idPrefixRejected(t *testing.T) {
	// Only $argon2id$ hashes are accepted. A `$2a$`-prefixed input (a sample
	// non-argon2id PHC string) must be rejected as unsupported format, not
	// verified — this guards against accidental reintroduction of fallback
	// code paths for retired algorithms.
	nonArgon2id := []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	if err := CompareHashAndPassword(nonArgon2id, []byte("pass")); err != ErrUnsupportedHashFormat {
		t.Errorf("expected ErrUnsupportedHashFormat for non-argon2id-prefixed input, got %v", err)
	}
}

func TestCompareHashAndPassword_InvalidFormats(t *testing.T) {
	tests := []struct {
		name        string
		hash        string
		password    string
		expectedErr error
	}{
		{
			name:        "MD5 format (unsupported)",
			hash:        "$1$12345678$0",
			password:    "pass",
			expectedErr: ErrUnsupportedHashFormat,
		},
		{
			name:        "Missing parts",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$salt",
			password:    "pass",
			expectedErr: ErrInvalidHashFormat,
		},
		{
			name:        "Invalid version",
			hash:        "$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA",
			password:    "pass",
			expectedErr: ErrInvalidHashFormat,
		},
		{
			name:        "Malformed parameters",
			hash:        "$argon2id$v=19$m=abc,t=def,p=ghi$c2FsdA$aGFzaA",
			password:    "pass",
			expectedErr: ErrInvalidHashFormat,
		},
		{
			name:        "Invalid base64 in salt",
			hash:        "$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",
			password:    "pass",
			expectedErr: ErrInvalidHashFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CompareHashAndPassword([]byte(tt.hash), []byte(tt.password))
			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}
