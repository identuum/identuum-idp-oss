// Package pkce is the public OSS seam for RFC 7636 (Proof Key
// for Code Exchange) verification. It exposes the single S256 verification
// primitive the authorization-code grant needs, with no dependency on the
// OSS `internal/` tree, so downstream callers — including the
// identuum-idp-ce overlay — can share ONE implementation of the check.
//
// Only the "S256" transform is implemented: the "plain" method is
// deliberately unsupported (Identuum issues and requires S256 challenges).
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// MethodS256 is the RFC 7636 §4.3 code_challenge_method this package
// verifies: the challenge is the base64url (no padding) encoding of the
// SHA-256 digest of the code_verifier.
const MethodS256 = "S256"

// Verify reports whether codeVerifier satisfies the S256 codeChallenge per
// RFC 7636 §4.6:
//
//	base64url_raw(SHA-256(codeVerifier)) == codeChallenge
//
// It returns false when either argument is empty (an absent verifier or an
// absent stored challenge can never be a valid proof), and otherwise
// compares the recomputed challenge to codeChallenge in constant time via
// crypto/subtle.ConstantTimeCompare (which also yields a non-match on any
// length difference). The verifier and challenge are never logged.
func Verify(codeVerifier, codeChallenge string) bool {
	if !ValidVerifier(codeVerifier) || codeChallenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(codeChallenge)) == 1
}

// ValidVerifier reports whether v has the RFC 7636 §4.1 shape: 43 to 128
// characters, each from the unreserved set [A-Z] [a-z] [0-9] "-" "." "_" "~".
func ValidVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}
