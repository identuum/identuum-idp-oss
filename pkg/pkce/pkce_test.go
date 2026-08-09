package pkce_test

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/pkg/pkce"
)

// TestVerify is table-driven and anchored on the RFC 7636 §4.6 worked
// example. The remaining rows pin the false-returning edges: a mismatched
// challenge, an empty verifier, and an empty challenge.
func TestVerify(t *testing.T) {
	// RFC 7636 Appendix B / §4.6 vector.
	const (
		rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	cases := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{
			name:      "rfc7636 §4.6 vector matches",
			verifier:  rfcVerifier,
			challenge: rfcChallenge,
			want:      true,
		},
		{
			name:      "wrong verifier does not match challenge",
			verifier:  "not-the-right-verifier-value-000000000000000",
			challenge: rfcChallenge,
			want:      false,
		},
		{
			name:      "correct verifier vs tampered challenge",
			verifier:  rfcVerifier,
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX", // last char flipped
			want:      false,
		},
		{
			name:      "empty verifier",
			verifier:  "",
			challenge: rfcChallenge,
			want:      false,
		},
		{
			name:      "empty challenge",
			verifier:  rfcVerifier,
			challenge: "",
			want:      false,
		},
		{
			name:      "both empty",
			verifier:  "",
			challenge: "",
			want:      false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pkce.Verify(tc.verifier, tc.challenge); got != tc.want {
				t.Fatalf("Verify(%q, %q) = %v, want %v", tc.verifier, tc.challenge, got, tc.want)
			}
		})
	}
}

// TestMethodS256 pins the exported method constant.
func TestMethodS256(t *testing.T) {
	if pkce.MethodS256 != "S256" {
		t.Fatalf("MethodS256 = %q, want \"S256\"", pkce.MethodS256)
	}
}
