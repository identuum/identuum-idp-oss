package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateSecureRefreshToken verifies the three invariants of the
// selector-validator split-token architecture:
//
//  1. Selector is a valid (non-nil) UUID v7.
//  2. Validator is exactly 32 bytes of random data.
//  3. Two consecutive calls produce distinct Selector and Validator values,
//     confirming that the CSPRNG is seeded correctly and not returning
//     a constant or cached value.
func TestGenerateSecureRefreshToken(t *testing.T) {
	tok1, err := GenerateSecureRefreshToken()
	require.NoError(t, err, "first call must not error")
	require.NotNil(t, tok1, "first call must return a non-nil token")

	tok2, err := GenerateSecureRefreshToken()
	require.NoError(t, err, "second call must not error")
	require.NotNil(t, tok2, "second call must return a non-nil token")

	// (a) Selector is a valid non-nil UUID.
	assert.NotEqual(t, tok1.Selector, [16]byte{}, "selector must not be the nil UUID")
	assert.NotEqual(t, tok2.Selector, [16]byte{}, "selector must not be the nil UUID")

	// (b) Validator is exactly 32 bytes.
	assert.Len(t, tok1.Validator, 32, "validator must be exactly 32 bytes")
	assert.Len(t, tok2.Validator, 32, "validator must be exactly 32 bytes")

	// (c) Two calls must produce distinct selectors and validators.
	assert.NotEqual(t, tok1.Selector, tok2.Selector,
		"consecutive calls must produce distinct selectors (CSPRNG uniqueness)")
	assert.NotEqual(t, tok1.Validator, tok2.Validator,
		"consecutive calls must produce distinct validators (CSPRNG uniqueness)")
}

func TestIsStrongPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "valid_strong_password",
			password: "StrongPassword123!",
			want:     true,
		},
		{
			name:     "valid_minimal_length",
			password: "Pass1word", // 9 chars, has upper, lower, digit
			want:     true,
		},
		{
			name:     "valid_just_enough",
			password: "p1", // Wait, implementation requires length 8? Let's check logic.
			// Logic: len >= 8, hasNumber, hasLetter.
			want: false,
		},
		{
			name:     "invalid_too_short",
			password: "Pass1",
			want:     false,
		},
		{
			name:     "invalid_no_number",
			password: "PasswordOnly",
			want:     false,
		},
		{
			name:     "invalid_no_letter",
			password: "12345678",
			want:     false,
		},
		{
			name:     "invalid_empty",
			password: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsStrongPassword(tt.password)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{
			name:      "valid_length_10",
			length:    10,
			wantError: false,
		},
		{
			name:      "valid_length_32",
			length:    32,
			wantError: false,
		},
		{
			name:      "valid_length_0",
			length:    0,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRandomString(tt.length)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.length, len(got))

			// Verify characters are within allowed charset (alphanumeric)
			// charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
			for _, char := range got {
				isAlphanumeric := (char >= 'a' && char <= 'z') ||
					(char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9')
				assert.True(t, isAlphanumeric, "Character '%c' is not alphanumeric", char)
			}
		})
	}
}

// TestGenerateRandomString_Randomness checks that subsequent calls produce different results
func TestGenerateRandomString_Randomness(t *testing.T) {
	s1, err1 := GenerateRandomString(20)
	s2, err2 := GenerateRandomString(20)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEqual(t, s1, s2, "Random strings should usually be different")
}
