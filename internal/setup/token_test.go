package setup

import (
	"strings"
	"testing"
)

// validTokenCharset is the base32 (RFC 4648) alphabet without padding —
// uppercase A-Z and digits 2-7. Anything else means the encoder picked
// the wrong table.
const validTokenCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func TestGenerateToken_LengthAndCharset(t *testing.T) {
	plain, hashHex, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if got := len(plain); got != 52 {
		t.Errorf("plaintext length = %d; want 52 (32 raw bytes → 52 unpadded base32 chars)", got)
	}
	for i, r := range plain {
		if !strings.ContainsRune(validTokenCharset, r) {
			t.Errorf("plaintext byte %d = %q is outside base32 charset", i, r)
		}
	}
	if strings.Contains(plain, "=") {
		t.Errorf("plaintext should not contain padding chars: %q", plain)
	}
	if got := len(hashHex); got != 64 {
		t.Errorf("hash length = %d; want 64 (SHA-256 hex)", got)
	}
	for i, r := range hashHex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("hash byte %d = %q is not lower-hex", i, r)
		}
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	seenHashes := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		plain, hash, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken iter %d: %v", i, err)
		}
		if _, dup := seen[plain]; dup {
			t.Errorf("duplicate plaintext at iter %d (should be cryptographically impossible)", i)
		}
		if _, dup := seenHashes[hash]; dup {
			t.Errorf("duplicate hash at iter %d", i)
		}
		seen[plain] = struct{}{}
		seenHashes[hash] = struct{}{}
	}
}

func TestVerifyToken_HappyPath(t *testing.T) {
	plain, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !VerifyToken(plain, hash) {
		t.Errorf("VerifyToken(matching pair) = false; want true")
	}
}

func TestVerifyToken_Mismatch(t *testing.T) {
	plain, hash, _ := GenerateToken()

	// Mutate one character.
	mutated := []byte(plain)
	if mutated[0] == 'A' {
		mutated[0] = 'B'
	} else {
		mutated[0] = 'A'
	}
	if VerifyToken(string(mutated), hash) {
		t.Errorf("VerifyToken(tampered, hash) = true; want false")
	}

	// Different valid token must not authorise.
	otherPlain, _, _ := GenerateToken()
	if VerifyToken(otherPlain, hash) {
		t.Errorf("VerifyToken(other valid token, hash) = true; want false")
	}
}

func TestVerifyToken_RefuseEmpty(t *testing.T) {
	plain, hash, _ := GenerateToken()
	if VerifyToken("", hash) {
		t.Errorf("VerifyToken(empty plaintext, hash) = true; want false")
	}
	if VerifyToken(plain, "") {
		t.Errorf("VerifyToken(plain, empty hash) = true; want false")
	}
	if VerifyToken("", "") {
		t.Errorf("VerifyToken(\"\", \"\") = true; want false")
	}
}

func TestVerifyToken_WrongLengthHash(t *testing.T) {
	plain, _, _ := GenerateToken()
	// Truncated hash: even if a prefix-match attack could shave bits,
	// the length check forbids it.
	if VerifyToken(plain, "deadbeef") {
		t.Errorf("VerifyToken(plain, short hash) = true; want false")
	}
	// Hash longer than 64 chars — also rejected outright.
	if VerifyToken(plain, strings.Repeat("a", 128)) {
		t.Errorf("VerifyToken(plain, oversized hash) = true; want false")
	}
}
