package service

import (
	"encoding/base32"
	"testing"
)

// Recovery codes are stored as an unkeyed SHA-256. Whoever reads the table can
// test guesses offline at billions a second, so a code must be too large to
// guess: at least 80 random bits (a 40-bit code falls in seconds).
func TestRecoveryCodes_AreAtLeast80BitsByDefault(t *testing.T) {
	codes, err := generateRecoveryCodes(defaultMFAEnrollmentRecoveryCodeCount, defaultMFAEnrollmentRecoveryCodeBytes)
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}
	if len(codes) != defaultMFAEnrollmentRecoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), defaultMFAEnrollmentRecoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(code)
		if err != nil {
			t.Fatalf("code is not base32: %v", err)
		}
		if bits := len(raw) * 8; bits < 80 {
			t.Errorf("a recovery code carries %d random bits; want at least 80", bits)
		}
		if seen[code] {
			t.Errorf("duplicate recovery code")
		}
		seen[code] = true
	}
}
