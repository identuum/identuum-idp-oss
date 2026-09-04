package main

// reach_test.go — RULE: MINT-REACHABILITY-1.
//
// The failure this rule exists to prevent is a change that reaches the
// running appliance shipping without a mint. So every subtest is a way the
// classifier could say SKIPPABLE when it must not: a source file, a
// dependency bump, a deployment file, a path nobody declared, and — the one
// that would quietly disarm the whole thing — a no-reach entry widened until
// it covers real code.

import (
	"strings"
	"testing"
)

// RULE: MINT-REACHABILITY-1
func TestRuleMintReachability1_OnlyDeclaredNoReachSkips_EverythingElseMints(t *testing.T) {
	t.Run("the declared no-reach set skips, and every path is justified by name", func(t *testing.T) {
		changed := []string{
			".github/workflows/ci.yml",
			"docs/DEPENDENCY-CURRENCY.md",
			"RULE-FLOOR.md",
			"ledger-amendments.json",
			"GATE-RUN.txt",
			"MINT-STATE.json",
			"cmd/identuum-idp/gate_witness_clean_head_test.go",
		}
		d := Decide(changed, NoReachSet)
		if d.Required {
			t.Fatalf("a documentation/CI/test-only change demanded a mint: %v", d.Reaching)
		}
		if len(d.NoReach) != len(changed) {
			t.Fatalf("not every path was justified: %+v", d.NoReach)
		}
		line := d.Line()
		if !strings.HasPrefix(line, "check OK: mint-reachability SKIPPABLE") {
			t.Fatalf("evidence line does not state the decision: %q", line)
		}
		for _, p := range changed {
			if !strings.Contains(line, p) {
				t.Fatalf("the skip does not name %s — a skip nobody can audit does not exist", p)
			}
		}
	})

	t.Run("source, deps, deployment and the harness all REQUIRE the mint", func(t *testing.T) {
		for _, p := range []string{
			"internal/service/local_login_service.go",
			"cmd/identuum-idp/main.go",
			"auth/acr_login.go",
			"go.mod",
			"go.sum",
			"deployment/Dockerfile.local",
			"Makefile",
			"e2e-full/scripts/full-run.sh",
			"src/app/login/page.tsx",
		} {
			d := Decide([]string{p}, NoReachSet)
			if !d.Required {
				t.Errorf("%s classified SKIPPABLE — it can reach the appliance", p)
			}
		}
	})

	t.Run("go.mod is NOT prose just because it sits beside prose", func(t *testing.T) {
		d := Decide([]string{"docs/README.md", "go.mod"}, NoReachSet)
		if !d.Required {
			t.Fatal("a dependency bump rode in under a documentation change")
		}
		if len(d.Reaching) != 1 || d.Reaching[0] != "go.mod" {
			t.Fatalf("reaching set = %v, want exactly [go.mod]", d.Reaching)
		}
	})

	t.Run("an UNKNOWN path fails closed and is named", func(t *testing.T) {
		d := Decide([]string{"something/nobody/declared.bin"}, NoReachSet)
		if !d.Required {
			t.Fatal("an undeclared path was treated as harmless — the classifier must fail closed")
		}
		if len(d.Unknown) != 1 {
			t.Fatalf("unknown set = %v, want the one path", d.Unknown)
		}
		if !strings.Contains(d.Line(), "something/nobody/declared.bin") {
			t.Fatalf("the line does not name the unknown path: %q", d.Line())
		}
	})

	t.Run("a *_test.go file skips but a non-test file with test in its name does NOT", func(t *testing.T) {
		if Decide([]string{"internal/service/mfa_verifier_test.go"}, NoReachSet).Required {
			t.Error("a _test.go file demanded a mint; the Go toolchain never builds it into the binary")
		}
		for _, p := range []string{"internal/service/testing.go", "internal/testsupport/helper.go"} {
			if !Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s classified SKIPPABLE — it is compiled into the binary", p)
			}
		}
	})

	t.Run("an empty change set is skippable and says why", func(t *testing.T) {
		d := Decide(nil, NoReachSet)
		if d.Required {
			t.Fatal("nothing changed and the mint was still demanded")
		}
		if !strings.Contains(d.Line(), "no change since the last minted witness") {
			t.Fatalf("line = %q", d.Line())
		}
	})

	t.Run("A WIDENED ENTRY MUST NOT SWALLOW REAL CODE", func(t *testing.T) {
		// The disarming mutation, held explicitly: if someone broadens an
		// entry — `docs/**` to `**`, or `**/*.md` to `**/*` — real source
		// must still classify as reaching. This subtest is what turns that
		// edit red.
		for _, widened := range []string{"**", "**/*", "*"} {
			set := append([]NoReachEntry{{Pattern: widened, Why: "widened by mistake"}}, NoReachSet...)
			d := Decide([]string{"internal/service/local_login_service.go"}, set)
			if !d.Required {
				t.Errorf("no-reach entry %q swallowed a source file — the mint would be skipped on a change that reaches the appliance", widened)
			}
		}
	})

	t.Run("matchPath does not let a prefix entry escape its directory", func(t *testing.T) {
		cases := map[string]bool{
			"docs/a/b.txt":     true,  // under docs/
			"docs":             true,  // the directory itself
			"docsy/evil.go":    false, // NOT under docs/
			"internal/docs.go": false,
		}
		for p, want := range cases {
			if got := matchPath("docs/**", p); got != want {
				t.Errorf("matchPath(docs/**, %s) = %v, want %v", p, got, want)
			}
		}
	})
}
