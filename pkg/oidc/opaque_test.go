package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// TestOpaqueMinter_Mint proves the second AccessTokenMinter implementation:
// a 256-bit base64url (unpadded) wire token whose storeKey is its SHA-256
// hex digest, independent of the claim values.
func TestOpaqueMinter_Mint(t *testing.T) {
	m := oidc.NewOpaqueMinter()
	claims := oidc.TokenClaims{
		Issuer:    "https://idp.test",
		Subject:   "user-1",
		IssuedAt:  time.Unix(1_700_000_000, 0),
		ExpiresAt: time.Unix(1_700_003_600, 0),
		JTI:       "ignored-jti",
		ActorType: "user",
		Extra:     map[string]any{"email": "a@example.com"},
	}

	wire, storeKey, err := m.Mint(context.Background(), claims)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Wire token decodes to exactly 32 bytes of base64url (no padding).
	raw, err := base64.RawURLEncoding.DecodeString(wire)
	if err != nil {
		t.Fatalf("wire token is not raw base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("wire entropy = %d bytes, want 32", len(raw))
	}

	// storeKey is the SHA-256 hex of the wire token.
	sum := sha256.Sum256([]byte(wire))
	if want := hex.EncodeToString(sum[:]); storeKey != want {
		t.Errorf("storeKey = %q, want SHA-256(wire) = %q", storeKey, want)
	}

	// Opaque tokens carry NO embedded claims — the wire token must not
	// contain the subject/email.
	if len(wire) == 0 || contains(wire, "user-1") || contains(wire, "a@example.com") {
		t.Errorf("opaque wire token leaked claim data: %q", wire)
	}
}

// TestOpaqueMinter_MintIsUnique proves two mints produce distinct tokens +
// distinct storeKeys (random entropy, not a fixed value).
func TestOpaqueMinter_MintIsUnique(t *testing.T) {
	m := oidc.NewOpaqueMinter()
	w1, k1, err := m.Mint(context.Background(), oidc.TokenClaims{})
	if err != nil {
		t.Fatalf("Mint 1: %v", err)
	}
	w2, k2, err := m.Mint(context.Background(), oidc.TokenClaims{})
	if err != nil {
		t.Fatalf("Mint 2: %v", err)
	}
	if w1 == w2 {
		t.Errorf("two mints produced identical wire tokens")
	}
	if k1 == k2 {
		t.Errorf("two mints produced identical storeKeys")
	}
}

// contains is a tiny substring helper (avoids importing strings just for
// the leak assertion).
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
