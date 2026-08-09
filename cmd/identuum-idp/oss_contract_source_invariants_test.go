// OSS CLI source-invariant pins.
//
// These tests read cmd/identuum-idp/main.go as plain text and assert
// the public-release OSS CLI contract is documented in-source so future
// prompts cannot silently regress it. The contract was simplified per
// docs/audit/release-readiness/oss-cli-flag-audit.md and the
// oss-cli-simplification changelog.
//
// The contract:
//
//   - The DEFAULT action (no subcommand) serves the FULL OSS IdP, with
//     the serving configuration read from the environment. The database
//     URL is REQUIRED (IDENTUUM_IDP_DATABASE_URL); when it is missing the
//     binary exits non-zero naming the variable rather than starting a
//     degraded "scaffold".
//   - The operator one-shots are SUBCOMMANDS: migrate, bootstrap,
//     recover-site-admin, show-setup-code (operator-run, env-fed, never
//     printed). The OSS binary has NO --setup flag (setup is bootstrap).
//   - The split-era serve flags (--gin-serve, --jwks-db, the stdlib
//     --serve smoke server) and the diagnostic flags (--oss-smoke*,
//     --db-check, --print-license-info, --check-feature, --get-limit) are
//     REMOVED. The old "scaffold … No auth, no /authorize, no /token"
//     framing is gone — the OSS runtime is the full IdP.
//
// Companion wire-level pins (unchanged; they still hold because the full
// IdP's /authorize and /token return 4xx — NOT 200 — without valid
// input, and the four discovery/health endpoints still return 200):
//   - identuum-idp-oss/Makefile target verify-oss-contract — host curl smoke.
//   - identuum-ui/e2e/oss-contract.spec.ts — browser-side wire contract.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readMainSource(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	path := filepath.Join(wd, "main.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	// PREMISE: the source under inspection must EXIST as text. Every caller
	// of this helper asserts an ABSENCE over the returned string, and an
	// empty string contains nothing — a zero-byte read here would turn all
	// of them green while measuring nothing (V4).
	if len(b) == 0 {
		t.Fatalf("main.go read as EMPTY — every source-invariant sweep over it would pass vacuously")
	}
	return string(b)
}

// TestOSSContract_DefaultActionServesFullIdP pins that the default
// action serves the full IdP from the environment and that the database
// URL is the required, named serving input.
func TestOSSContract_DefaultActionServesFullIdP(t *testing.T) {
	src := readMainSource(t)
	required := []string{
		"serve the full OSS IdP",
		"IDENTUUM_IDP_DATABASE_URL",
	}
	for _, pat := range required {
		if !strings.Contains(src, pat) {
			t.Errorf("OSS main.go must document the default serve contract (missing %q)", pat)
		}
	}
}

// TestOSSContract_NoScaffoldFraming pins the removal of the split-era
// scaffold framing and serve flags. If a future change reintroduces a
// scaffold mode or the removed flags, this fires.
func TestOSSContract_NoScaffoldFraming(t *testing.T) {
	src := readMainSource(t)
	forbidden := []string{
		"No auth, no /authorize, no /token", // the old scaffold lie
		"gin-serve",                         // removed serve flag
		"oss-smoke",                         // removed diagnostic
		"print-license-info",                // removed diagnostic
		"check-feature",                     // removed diagnostic
	}
	for _, pat := range forbidden {
		if strings.Contains(src, pat) {
			t.Errorf("OSS main.go must NOT contain the removed/scaffold token %q; the OSS runtime is the full IdP and the split-era flags are gone", pat)
		}
	}
}

// TestOSSContract_SubcommandsRegistered pins that the four operator
// one-shots are registered as subcommands. bootstrap + recover-site-admin
// are the supported headless operator paths (the OSS binary has no
// --setup flag).
func TestOSSContract_SubcommandsRegistered(t *testing.T) {
	src := readMainSource(t)
	required := []string{
		`"migrate"`,
		`"bootstrap"`,
		`"recover-site-admin"`,
		`"show-setup-code"`,
	}
	for _, sub := range required {
		if !strings.Contains(src, sub) {
			t.Errorf("OSS binary must register the %s subcommand", sub)
		}
	}
}

// TestOSSContract_NoSetupFlag pins that the OSS binary does NOT register
// a --setup-like flag. Setup against an OSS runtime is `bootstrap`
// (operator-run, env-var-fed). CE has --setup — but CE is a separate
// repo and binary.
func TestOSSContract_NoSetupFlag(t *testing.T) {
	src := readMainSource(t)
	patterns := []string{
		`fs.StringVar(&setup`,
		`fs.BoolVar(&setup`,
		`fs.StringVar(&setupDir`,
		`fs.BoolVar(&runSetup`,
		`fs.BoolVar(&plainSetup`,
	}
	for _, pat := range patterns {
		if strings.Contains(src, pat) {
			t.Errorf(
				"OSS binary must NOT register a --setup-like CLI flag (matched %q). "+
					"Use the bootstrap subcommand instead. If intentional, also update "+
					"identuum-ui/e2e/oss-contract.spec.ts, the verify-oss-contract Makefile "+
					"target, and wiki/repos/identuum-idp-oss.md.",
				pat,
			)
		}
	}
}
