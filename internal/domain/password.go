package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

var (
	ErrPasswordTooShort   = errors.New("password is too short")
	ErrPasswordTooLong    = errors.New("password is too long")
	ErrPasswordNoUpper    = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLower    = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoNumber   = errors.New("password must contain at least one number")
	ErrPasswordNoSpecial  = errors.New("password must contain at least one special character")
	ErrPasswordUnsafeChar = errors.New("password contains forbidden characters")
)

// MaxPasswordLength caps the size of any candidate password. argon2id's
// pre-hash phase (BLAKE2b) is O(input_size); without a cap, the 1 MB request
// body limit would let a single legitimate request submit a ~1 MB password
// and add ~10 ms of CPU per verification on top of the ~150 ms argon2id
// memory pass. OWASP Password Storage Cheat Sheet recommends 128.
const MaxPasswordLength = 128

// safeSpecialChars defines the allowed set of special characters.
// `$` is deliberately excluded — it is present in forbiddenChars (shell-injection
// defense) and would never pass the earlier forbidden-char gate, so advertising
// it in the "allowed specials" error message would mislead users.
const safeSpecialChars = "!@#%^&*-+=?_~"

// forbiddenChars defines explicitly unsafe characters for shells
const forbiddenChars = "'\"$\\;|<>()`"

// ValidatePasswordPolicy enforces password rules according to the organization's policy.
//
// When complexityEnabled is true (the default for all organizations), the full set of
// rules apply:
//  1. Minimum length (configurable)
//  2. At least 1 uppercase letter
//  3. At least 1 lowercase letter
//  4. At least 1 number
//  5. At least 1 special character (from the safe set)
//  6. No forbidden characters
//
// When complexityEnabled is false, only rules 1 and 6 are checked — minimum length
// and no forbidden characters. This is the "relaxed" mode an org admin may enable.
func ValidatePasswordPolicy(password string, minLength int, complexityEnabled bool) error {
	// Apply max-length cap before any other check so the rule holds in both
	// strict and relaxed complexity modes (registration, change-password,
	// password-reset, activation, SCIM provisioning all funnel here).
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("%w: maximum %d characters allowed", ErrPasswordTooLong, MaxPasswordLength)
	}
	if len(password) < minLength {
		return fmt.Errorf("%w: minimum %d characters required", ErrPasswordTooShort, minLength)
	}

	// Always reject forbidden characters regardless of complexity setting.
	for _, char := range password {
		if strings.ContainsRune(forbiddenChars, char) {
			return fmt.Errorf("%w: character '%c' is not allowed", ErrPasswordUnsafeChar, char)
		}
	}

	if !complexityEnabled {
		return nil
	}

	// Complexity rules (only when complexityEnabled == true).
	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case strings.ContainsRune(safeSpecialChars, char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return ErrPasswordNoUpper
	}
	if !hasLower {
		return ErrPasswordNoLower
	}
	if !hasNumber {
		return ErrPasswordNoNumber
	}
	if !hasSpecial {
		return fmt.Errorf("%w: allowed specials are %s", ErrPasswordNoSpecial, safeSpecialChars)
	}

	return nil
}

// ValidatePassword enforces the full password complexity rules (strict mode).
// It is equivalent to ValidatePasswordPolicy with complexityEnabled = true.
// Use this for activation flows, CLI setup, and any context where the org setting
// must not relax the requirements.
func ValidatePassword(password string, minLength int) error {
	return ValidatePasswordPolicy(password, minLength, true)
}
