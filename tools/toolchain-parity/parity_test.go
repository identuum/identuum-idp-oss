package main

// parity_test.go — RULE: TOOLCHAIN-PARITY-1.
//
// The drift this gate exists to catch was invisible for weeks, so the tests
// are about the ways a parity check can LOOK green while comparing nothing:
// a pin the parser missed, a tool that is not installed, a decorated version
// string read as a mismatch, a digest pin left behind by an edit — and the
// empty list, which is the purest decoration of all.

import (
	"strings"
	"testing"
)

const wfEnv = `name: ci

on:
  push:

env:
  IDENTUUM_IDP_DEPLOYMENT_MODE: dev
  # a comment inside the block
  RULEFLOOR_VERSION: v0.9.0
  STATICCHECK_VERSION: v0.8.1
  GRYPE_VERSION: v0.118.0
  GOVULNCHECK_VERSION: v1.7.0
  GATE_WITNESS_SHA256: "1377b103674b75f97d171fa41fed1651863ca9c0244ee51972b125c266d9ed5e"

jobs:
  verify:
    env:
      NOT_THE_TOP_LEVEL: nope
`

func agreeing() []Pin {
	return []Pin{
		{Tool: "rulefloor", Source: "workflow env RULEFLOOR_VERSION", Declared: "0.9.0", Observed: "0.9.0"},
		{Tool: "go", Source: "go.mod go directive", Declared: "1.27.1", Observed: "1.27.1"},
	}
}

// RULE: CI-LOCAL-PARITY-1
func TestRuleCILocalParity1_MismatchFails_MissingFails_EmptyListFails(t *testing.T) {
	t.Run("agreement passes and names every pin it compared", func(t *testing.T) {
		_, summary, ok := Decide(agreeing())
		if !ok {
			t.Fatalf("agreement must pass: %s", summary)
		}
		if !strings.HasPrefix(summary, "check OK: toolchain-parity 2 pins agree") {
			t.Fatalf("evidence line does not carry the count: %q", summary)
		}
		for _, want := range []string{"rulefloor 0.9.0", "go 1.27.1"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("evidence line %q omits %q", summary, want)
			}
		}
	})

	t.Run("a version mismatch FAILS and names both sides", func(t *testing.T) {
		pins := append(agreeing(), Pin{
			Tool: "grype", Source: "workflow env GRYPE_VERSION",
			Declared: "0.117.0", Observed: "0.118.0",
		})
		failures, summary, ok := Decide(pins)
		if ok {
			t.Fatal("a disagreeing toolchain passed the gate")
		}
		if len(failures) != 1 || failures[0].Tool != "grype" {
			t.Fatalf("failures = %+v, want just grype", failures)
		}
		for _, want := range []string{"grype", "declares 0.117.0", "this machine has 0.118.0"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("failure line %q omits %q", summary, want)
			}
		}
	})

	t.Run("a STALE DIGEST pin fails — the drift that would have broken CI", func(t *testing.T) {
		// GATE_WITNESS_SHA256 naming the pre-instrumentation script while the
		// repository carries the new one. CI verifies that file with
		// `sha256sum -c`, so this is a hard CI failure that no local gate saw.
		pins := append(agreeing(), Pin{
			Tool: "gate-witness.sh", Source: "workflow env GATE_WITNESS_SHA256",
			Declared: "48eeba51aac38bed3a70b5c547f8a898e0c6042c2b77fb5fcb8b2f62a502926b",
			Observed: "1377b103674b75f97d171fa41fed1651863ca9c0244ee51972b125c266d9ed5e",
		})
		if _, summary, ok := Decide(pins); ok {
			t.Fatalf("a stale digest pin passed: %s", summary)
		}
	})

	t.Run("a missing declaration or a missing tool FAILS, never passes", func(t *testing.T) {
		noPin := append(agreeing(), Pin{Tool: "grype", Source: "workflow env GRYPE_VERSION", Declared: "", Observed: "0.118.0"})
		if _, s, ok := Decide(noPin); ok {
			t.Fatalf("an undeclared tool passed: %s", s)
		}
		notInstalled := append(agreeing(), Pin{Tool: "grype", Source: "workflow env GRYPE_VERSION", Declared: "0.118.0", Observed: ""})
		_, s, ok := Decide(notInstalled)
		if ok {
			t.Fatalf("an uninstalled tool passed: %s", s)
		}
		if !strings.Contains(s, "(missing)") {
			t.Fatalf("failure line does not say what is missing: %q", s)
		}
	})

	t.Run("an empty comparison list FAILS — a gate that compares nothing is a decoration", func(t *testing.T) {
		if _, s, ok := Decide(nil); ok {
			t.Fatalf("the empty list passed: %s", s)
		}
	})

	t.Run("the workflow env parser finds the top-level pins and stops at the block", func(t *testing.T) {
		env := ParseWorkflowEnv([]byte(wfEnv))
		for k, want := range map[string]string{
			"RULEFLOOR_VERSION":   "v0.9.0",
			"STATICCHECK_VERSION": "v0.8.1",
			"GRYPE_VERSION":       "v0.118.0",
			"GOVULNCHECK_VERSION": "v1.7.0",
			"GATE_WITNESS_SHA256": "1377b103674b75f97d171fa41fed1651863ca9c0244ee51972b125c266d9ed5e",
		} {
			if env[k] != want {
				t.Fatalf("env[%s] = %q, want %q", k, env[k], want)
			}
		}
		// A job-level env must NOT be read as a workflow declaration.
		if _, found := env["NOT_THE_TOP_LEVEL"]; found {
			t.Fatal("the parser walked past the top-level env block")
		}
	})

	t.Run("real tool output normalizes to the pinned form", func(t *testing.T) {
		cases := []struct{ kind, raw, want string }{
			{"staticcheck", "2026.2.1 (0.8.1)", "0.8.1"},
			{"grype", "grype 0.118.0", "0.118.0"},
			{"govulncheck", "Go: go1.27.1\nScanner: govulncheck@v1.7.0\n", "1.7.0"},
			{"rulefloor", `{"schema_version":"rulefloor.version.v1","version":"v0.9.0"}`, "0.9.0"},
			{"go", "go version go1.27.1 darwin/arm64", "1.27.1"},
			{"go", "go 1.27.1", "1.27.1"},
			{"grype", "v0.118.0", "0.118.0"},
			{"sha256", "1377B103674B75F9", "1377b103674b75f9"},
			// Silence is never agreement.
			{"grype", "command not found", ""},
			{"rulefloor", "", ""},
		}
		for _, c := range cases {
			if got := Normalize(c.kind, c.raw); got != c.want {
				t.Errorf("Normalize(%s, %q) = %q, want %q", c.kind, c.raw, got, c.want)
			}
		}
	})

	t.Run("a v prefix on one side only is NOT a mismatch once normalized", func(t *testing.T) {
		if Normalize("grype", "v0.118.0") != Normalize("grype", "grype 0.118.0") {
			t.Fatal("the v prefix would fire a false mismatch")
		}
	})

	t.Run("EVERY declared pin normalizes through KindPin, never a tool normalizer", func(t *testing.T) {
		// The bug this pins: running an OBSERVED-side normalizer over a
		// DECLARED pin finds nothing, so a pin that is plainly present reads
		// as "(missing)" — the gate then reports a mismatch for a toolchain
		// that agrees, and the real drift is lost in the noise. The two sides
		// are shaped differently and must normalize differently.
		env := ParseWorkflowEnv([]byte(wfEnv))
		for key, want := range map[string]string{
			"RULEFLOOR_VERSION":   "0.9.0",
			"STATICCHECK_VERSION": "0.8.1",
			"GRYPE_VERSION":       "0.118.0",
			"GOVULNCHECK_VERSION": "1.7.0",
		} {
			if got := Normalize(KindPin, env[key]); got != want {
				t.Errorf("Normalize(KindPin, %s=%q) = %q, want %q — a present pin must never read as missing",
					key, env[key], got, want)
			}
		}
		if got := Normalize(KindPin, "go 1.27.1"); got != "1.27.1" {
			t.Errorf("go.mod directive normalized to %q, want 1.27.1", got)
		}
	})
}
