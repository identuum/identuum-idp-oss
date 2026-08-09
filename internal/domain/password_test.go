package domain

import (
	"strings"
	"testing"
)

func TestValidatePassword(t *testing.T) {

	tests := []struct {
		wantErr   error
		name      string
		password  string
		minLength int
	}{
		{
			name:      "Valid Password",
			password:  "StrongPass1!",
			minLength: 8,
			wantErr:   nil,
		},
		{
			name:      "Valid Long Password",
			password:  "VeryLongStrongPass123!@#",
			minLength: 12,
			wantErr:   nil,
		},
		{
			name:      "Too Short",
			password:  "Short1!",
			minLength: 8,
			wantErr:   ErrPasswordTooShort,
		},
		{
			name:      "Missing Uppercase",
			password:  "weakpass1!",
			minLength: 8,
			wantErr:   ErrPasswordNoUpper,
		},
		{
			name:      "Missing Lowercase",
			password:  "WEAKPASS1!",
			minLength: 8,
			wantErr:   ErrPasswordNoLower,
		},
		{
			name:      "Missing Number",
			password:  "NoNumber!",
			minLength: 8,
			wantErr:   ErrPasswordNoNumber,
		},
		{
			name:      "Missing Special",
			password:  "NoSpecial1",
			minLength: 8,
			wantErr:   ErrPasswordNoSpecial,
		},
		{
			name:      "Unsafe Character (Quote)",
			password:  "Unsafe'1!",
			minLength: 8,
			wantErr:   ErrPasswordUnsafeChar,
		},
		{
			name:      "Unsafe Character (Semicolon)",
			password:  "Unsafe;1!",
			minLength: 8,
			wantErr:   ErrPasswordUnsafeChar,
		},
		{
			name:      "Unsafe Character (Dollar)",
			password:  "Unsafe$1!",
			minLength: 8,
			wantErr:   ErrPasswordUnsafeChar,
		},
		{
			name:      "Configurable Min Length",
			password:  "Pass123!", // 8 chars
			minLength: 10,
			wantErr:   ErrPasswordTooShort, // Expect fail if min is 10
		},
		{
			// §1.4 — argon2id pre-hash is O(input_size). Reject before the
			// hash even runs to keep verification cost bounded.
			name:      "Too Long",
			password:  strings.Repeat("Aa1!", (MaxPasswordLength/4)+1), // > MaxPasswordLength
			minLength: 8,
			wantErr:   ErrPasswordTooLong,
		},
		{
			// Boundary: a password of exactly MaxPasswordLength chars that
			// satisfies all complexity rules must pass.
			name:      "At Maximum Length",
			password:  "Aa1!" + strings.Repeat("a", MaxPasswordLength-4), // 128 chars total
			minLength: 8,
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, tt.minLength)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidatePassword() error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidatePassword() expected error %v, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					// We check contains because some errors are wrapped with %w or extra info
					t.Errorf("ValidatePassword() error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestValidatePasswordPolicy_RelaxedMode exercises the per-organization
// complexityEnabled=false branch. Only length and forbidden-char checks apply;
// upper/lower/number/special are waived.
func TestValidatePasswordPolicy_RelaxedMode(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		minLength int
		wantErr   error
	}{
		{
			// Lacks upper/number/special but satisfies length — relaxed mode accepts.
			name:      "simple password accepted",
			password:  "simplepass",
			minLength: 8,
			wantErr:   nil,
		},
		{
			// Forbidden chars remain rejected even in relaxed mode.
			name:      "forbidden dollar rejected in relaxed mode",
			password:  "simple$pass",
			minLength: 8,
			wantErr:   ErrPasswordUnsafeChar,
		},
		{
			// Length check still enforced.
			name:      "too short rejected in relaxed mode",
			password:  "short",
			minLength: 8,
			wantErr:   ErrPasswordTooShort,
		},
		{
			// Cap applies in relaxed mode too — argon2id input cost is the
			// same regardless of which complexity rules are toggled.
			name:      "too long rejected in relaxed mode",
			password:  strings.Repeat("a", MaxPasswordLength+1),
			minLength: 8,
			wantErr:   ErrPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tt.password, tt.minLength, false)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidatePasswordPolicy(relaxed) error = %v, wantErr nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidatePasswordPolicy(relaxed) expected error %v, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("ValidatePasswordPolicy(relaxed) error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestValidatePassword_MissingSpecialErrorMessageExcludesDollar guards the
// wire-format contract: the error message advertising the "allowed specials"
// set must not include `$`, which is rejected as a forbidden (shell-injection)
// character before the complexity check even runs.
func TestValidatePassword_MissingSpecialErrorMessageExcludesDollar(t *testing.T) {
	err := ValidatePassword("NoSpecial1", 8)
	if err == nil {
		t.Fatalf("expected ErrPasswordNoSpecial, got nil")
	}
	if strings.Contains(err.Error(), "$") {
		t.Errorf("ErrPasswordNoSpecial message must not advertise `$` as valid; got: %v", err)
	}
}
