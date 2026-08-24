package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Every secret the crypto service stores is AES-GCM ciphertext under the
// active key that round-trips through Decrypt, and a key that did not seal a
// ciphertext fails closed — a v2 ciphertext's key id must resolve to a held
// key, and an unkeyed ciphertext under one key never opens under another.
// Plaintext is never the stored form.
// RULE: ATREST-CIPHER-1
func TestCryptoService_AtRestCipherFailsClosed(t *testing.T) {
	svc, err := NewCryptoService(randomHexKey(t))
	if err != nil {
		t.Fatalf("NewCryptoService: %v", err)
	}

	// Stored form is versioned ciphertext, not plaintext, and round-trips.
	const secret = "mfa-seed-and-friends"
	ct, err := svc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(ct, "v2:") {
		t.Fatalf("stored form must be a v2 ciphertext, got prefix %.3q", ct)
	}
	if ct == secret || strings.Contains(ct, secret) {
		t.Fatalf("plaintext leaked into the stored ciphertext")
	}
	got, err := svc.Decrypt(ct)
	if err != nil || got != secret {
		t.Fatalf("round-trip failed: got=%q err=%v", got, err)
	}

	// A DIFFERENT service (different key, hence different key id) cannot open
	// the v2 ciphertext: its key id does not resolve to a held key.
	other, err := NewCryptoService(randomHexKey(t))
	if err != nil {
		t.Fatalf("NewCryptoService(other): %v", err)
	}
	if _, err := other.Decrypt(ct); err == nil {
		t.Fatalf("a foreign key opened a v2 ciphertext it never sealed (must fail closed)")
	}

	// An unkeyed (v1) ciphertext sealed under one key must not open under
	// another — the GCM tag rejects the wrong key.
	keyA := randomHexKey(t)
	svcA, _ := NewCryptoService(keyA)
	keyABytes, err := hex.DecodeString(keyA)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	v1 := craftV1Ciphertext(t, keyABytes, secret)
	if out, err := svcA.Decrypt(v1); err != nil || out != secret {
		t.Fatalf("PREMISE FAILED: v1 ciphertext must open under its own key: got=%q err=%v", out, err)
	}
	svcB, _ := NewCryptoService(randomHexKey(t))
	if _, err := svcB.Decrypt(v1); err == nil {
		t.Fatalf("a foreign key opened a v1 ciphertext it never sealed (must fail closed)")
	}

	// An unknown v2 key id is a permanent, explicit failure (no fallback).
	if _, err := svc.Decrypt("v2:deadbeefdeadbeef:AAAA"); err == nil {
		t.Fatalf("an unknown v2 key id must be refused, not silently retried")
	}
}
