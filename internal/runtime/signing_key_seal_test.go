package runtime

import "testing"

// An ACTIVE signing key that cannot be decrypted must be treated as the
// SIGNING-KEY-SEAL brick (which the boot check turns into a FATAL health
// fault), while a not-yet-configured install (zero active rows) and a healthy
// install (active rows all usable) must NOT fault. Hermetic: pure predicate.
// RULE: SIGNING-KEY-SEAL-1
func TestSigningKeySealFault(t *testing.T) {
	cases := []struct {
		name       string
		activeRows int
		usableKeys int
		wantFault  bool
	}{
		// The brick: active rows exist, none decrypt.
		{"active rows, none usable", 1, 0, true},
		{"several active rows, none usable", 3, 0, true},
		// Healthy: active rows, at least one usable.
		{"active rows, one usable", 1, 1, false},
		{"active rows, all usable", 3, 3, false},
		{"active rows, some usable", 3, 1, false},
		// Not yet set up: no active rows at all — must stay healthy.
		{"no active rows", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := signingKeySealFault(tc.activeRows, tc.usableKeys); got != tc.wantFault {
				t.Fatalf("signingKeySealFault(%d, %d) = %v, want %v",
					tc.activeRows, tc.usableKeys, got, tc.wantFault)
			}
		})
	}
}
