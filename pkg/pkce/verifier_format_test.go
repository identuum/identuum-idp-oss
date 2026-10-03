package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RFC 7636 §4.1: a code_verifier is 43 to 128 characters from the unreserved
// set [A-Z] [a-z] [0-9] "-" "." "_" "~". A verifier outside that shape never
// verifies, even when its S256 transform matches the stored challenge.
func TestVerify_EnforcesVerifierFormat(t *testing.T) {
	good := strings.Repeat("aB3-._~", 7)[:43]
	if !Verify(good, s256(good)) {
		t.Fatal("a 43-character unreserved verifier must verify")
	}
	long := strings.Repeat("x", 128)
	if !Verify(long, s256(long)) {
		t.Fatal("a 128-character verifier must verify")
	}
	for name, bad := range map[string]string{
		"too short":     "a",
		"42 characters": strings.Repeat("x", 42),
		"129 chars":     strings.Repeat("x", 129),
		"space":         strings.Repeat("x", 42) + " ",
		"plus sign":     strings.Repeat("x", 42) + "+",
	} {
		if Verify(bad, s256(bad)) {
			t.Errorf("%s: a malformed verifier must not verify", name)
		}
	}
}
