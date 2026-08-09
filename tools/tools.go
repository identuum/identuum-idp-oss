package tools

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

var (
	nonAlphanumericRegex = regexp.MustCompile(`[^a-z0-9]+`)
)

// GenerateSlug creates a URL-safe slug from a string
// - Converts to lowercase
// - Replaces spaces and special characters with hyphens
// - Trims hyphens from ends
func GenerateSlug(input string) string {
	slug := strings.ToLower(input)
	slug = nonAlphanumericRegex.ReplaceAllString(slug, "-")
	return strings.Trim(slug, "-")
}

// IsValidSlug checks if the slug contains only lowercase alphanumeric characters and hyphens
func IsValidSlug(slug string) bool {
	if len(slug) == 0 || len(slug) > 63 {
		return false
	}
	// Must start and end with alphanumeric
	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}
	// Only lowercase alphanumeric and hyphens allowed
	for _, c := range slug {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	// No double hyphens
	if strings.Contains(slug, "--") {
		return false
	}
	return true
}

// GenerateSecureRefreshToken generates a secure refresh token with selector/validator split
// Returns the SecureRefreshToken struct containing selector and raw validator bytes
func GenerateSecureRefreshToken() (*domain.SecureRefreshToken, error) {
	// Generate 32 bytes of cryptographically secure random data for the validator
	validator := make([]byte, 32)
	if _, err := rand.Read(validator); err != nil {
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}

	selector, sErr := uuidgen.NewV7()
	if sErr != nil {
		return nil, fmt.Errorf("failed to generate refresh token selector: %w", sErr)
	}

	return &domain.SecureRefreshToken{
		Selector:  selector,  // UUID v7 for public selector
		Validator: validator, // Raw bytes to be hashed before storage
	}, nil
}

// IsValidEmail was removed by `agent-claude-20260624-idp-oss-user-email-format-wirein`.
// It was a 130-line homegrown RFC 5322 validator with cyclomatic complexity
// 50, never called from any production path. Email format validation is now
// done at the User domain layer via net/mail.ParseAddress in
// (*User).Validate(). If you find yourself wanting an "is this a valid
// email" predicate from this package, use net/mail.ParseAddress directly.

// SanitizeEmail normalizes and sanitizes email input to prevent duplicates with different whitespace patterns
// Applies the following transformations:
// - Trims leading/trailing whitespace
// - Converts to lowercase for case-insensitive comparison
// - Removes any internal whitespace (spaces, tabs, newlines)
// This ensures consistent email storage and prevents database inefficiency from duplicate patterns
func SanitizeEmail(email string) string {
	// Trim whitespace from both ends
	email = strings.TrimSpace(email)

	// Convert to lowercase for case-insensitive handling
	email = strings.ToLower(email)

	// Remove any internal whitespace characters (spaces, tabs, newlines)
	email = strings.ReplaceAll(email, " ", "")
	email = strings.ReplaceAll(email, "\t", "")
	email = strings.ReplaceAll(email, "\n", "")
	email = strings.ReplaceAll(email, "\r", "")

	return email
}

// SanitizeName normalizes a display name input: trims surrounding whitespace,
// collapses repeated internal spaces, and removes control characters.
// It is semantically equivalent to SanitizeString but named explicitly for name fields.
func SanitizeName(name string) string {
	return SanitizeString(name)
}

// SanitizeString performs general string sanitization to prevent whitespace-related issues
// - Trims leading/trailing whitespace
// - Normalizes internal whitespace to single spaces
// - Removes control characters
func SanitizeString(input string) string {
	// Trim whitespace from both ends
	input = strings.TrimSpace(input)

	// Replace multiple consecutive spaces with a single space
	for strings.Contains(input, "  ") {
		input = strings.ReplaceAll(input, "  ", " ")
	}

	// Remove control characters (tabs, newlines, carriage returns)
	input = strings.ReplaceAll(input, "\t", " ")
	input = strings.ReplaceAll(input, "\n", " ")
	input = strings.ReplaceAll(input, "\r", " ")

	// Final cleanup in case the replacements created double spaces
	for strings.Contains(input, "  ") {
		input = strings.ReplaceAll(input, "  ", " ")
	}

	return strings.TrimSpace(input)
}

// GenerateRandomString generates a secure random string of given length using base62 (alphanumeric)
func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("secure random generation failed: %w", err)
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

// IsStrongPassword checks if the password meets complexity requirements
func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	// Check for at least one number and one letter
	hasNumber := false
	hasLetter := false
	for _, c := range password {
		if c >= '0' && c <= '9' {
			hasNumber = true
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
	}
	return hasNumber && hasLetter
}

// HashToken generates a SHA256 hash of the token
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
