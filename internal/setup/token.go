// Package setup implements the first-run appliance setup foundation for
// identuum-idp-oss: a singleton state machine, a setup-token primitive
// and file persistence layer, and the orchestration service consumed by
// the /api/setup/* HTTP surface.
//
// The contract — derived from the appliance-install-UX owner decisions
// (D-IDP-INSTALL-09, D-IDP-INSTALL-10, D-IDP-INSTALL-11, D-IDP-INSTALL-19,
// D-IDP-INSTALL-20) — is:
//
//   - The IDP generates the setup token; the UI never produces one.
//   - The plaintext is stored only in the data-volume file
//     ($DATA_DIR/setup-token.txt, mode 0600) plus the on-boot log line;
//     the database keeps only the SHA-256 hash.
//   - After successful wizard completion the file is deleted and the
//     hash is cleared, and /api/setup/{verify-token,complete} respond
//     410 Gone for any further attempt.
//   - The setup token is wizard-authorisation only; it is NOT the
//     site-administrator credential.
package setup

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
)

// tokenRawBytes controls the entropy of the generated setup token. 32
// raw bytes encode to 52 unpadded base32 characters — long enough to be
// resistant to online guessing under any realistic rate limit, short
// enough to copy out of `docker logs` in one go.
const tokenRawBytes = 32

// ErrTokenInvalid is returned by Service.VerifyToken / Service.Complete
// when the plaintext does not match the stored hash. Handlers map this
// to HTTP 401; the body never echoes the candidate value.
var ErrTokenInvalid = errors.New("setup token invalid")

// GenerateToken returns (plaintext, hashHex, err). The plaintext is
// shown to the operator exactly via the boot log + token file; the hash
// is what the database keeps. base32 (RFC 4648) without padding so the
// result has no `=` characters and survives shell, JSON, URL, and
// docker-log copy/paste cleanly.
func GenerateToken() (string, string, error) {
	buf := make([]byte, tokenRawBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("setup: generate token: %w", err)
	}
	plaintext := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return plaintext, crypto.HashToken(plaintext), nil
}

// VerifyToken compares a candidate plaintext against a stored SHA-256
// hash in constant time. Empty inputs always return false (so a missing
// file or cleared hash never accidentally authorises a wizard call).
func VerifyToken(plaintext, hashHex string) bool {
	if plaintext == "" || hashHex == "" {
		return false
	}
	candidate := crypto.HashToken(plaintext)
	if len(candidate) != len(hashHex) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(hashHex)) == 1
}
