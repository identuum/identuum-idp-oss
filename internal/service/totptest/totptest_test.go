package totptest

import (
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// The RFC 6238 test-vector seed ("12345678901234567890" in base32), padded.
const testSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPTest_MatchesTheProductionPrimitive(t *testing.T) {
	key, err := base32.StdEncoding.DecodeString(testSeed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, counter := range []uint64{0, 1, 59 / PeriodSeconds, 1111111109 / PeriodSeconds, 20000000000 / PeriodSeconds} {
		got, err := HOTP(testSeed, counter)
		if err != nil {
			t.Fatalf("HOTP(%d): %v", counter, err)
		}
		if want := totp.Code(key, counter, Digits); got != want {
			t.Fatalf("HOTP(%d) = %s, want pkg/totp's %s", counter, got, want)
		}
	}
	// RFC 6238 Appendix B, SHA-1, T=59 → 94287082 (8 digits); the last six are
	// what a six-digit verifier compares.
	got, _ := HOTP(testSeed, 1)
	if got != "287082" {
		t.Fatalf("RFC 6238 vector at T=59: got %s, want 287082", got)
	}
	// A NoPad seed with spaces decodes the way the production verifier
	// normalises it.
	noPad := strings.TrimRight(testSeed, "=")
	spaced := noPad[:8] + " " + strings.ToLower(noPad[8:])
	a, err := HOTP(spaced, 7)
	if err != nil {
		t.Fatalf("normalised seed: %v", err)
	}
	b, _ := HOTP(testSeed, 7)
	if a != b {
		t.Fatalf("normalisation changed the code: %s vs %s", a, b)
	}
	at := time.Date(2026, 9, 16, 12, 0, 5, 0, time.UTC)
	cur, _ := CodeAt(testSeed, at, 0)
	next, _ := CodeAt(testSeed, at, 1)
	step, _ := HOTP(testSeed, Step(at))
	if cur != step || cur == next {
		t.Fatalf("CodeAt: current %s (step %s), next %s", cur, step, next)
	}
	if _, err := HOTP("not-base32!", 0); err == nil {
		t.Fatal("an undecodable secret must be refused")
	}
}

// TestTOTPTest_IsTheOnlyHOTPStepInThisModuleTests pins the reason this package
// exists: no other test file of the module writes the HMAC-SHA1 step by hand.
// RED FIRST: internal/handlers/auth_mfa_recovery_codes_test.go and
// internal/e2e/login_mfa_enrolment_http_test.go both did.
func TestTOTPTest_IsTheOnlyHOTPStepInThisModuleTests(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	var inlined []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".gograph", "bin", "conformance":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// The needle is assembled so this file does not name itself.
		if strings.Contains(string(src), "hmac.New("+"sha1.New") {
			rel, _ := filepath.Rel(root, p)
			inlined = append(inlined, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(inlined) != 0 {
		t.Fatalf("the HOTP step is written by hand in test files that should use internal/service/totptest: %v", inlined)
	}
}
