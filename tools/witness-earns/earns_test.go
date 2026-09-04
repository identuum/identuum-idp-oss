package main

import (
	"strings"
	"testing"
)

// RULE: WITNESS-EARNS-ITS-CYCLE-1
func TestRuleWitnessEarnsItsCycle1_RecordOnlyIsRefused_SubstantiveIsEarned(t *testing.T) {
	t.Run("the exact shape from history is REFUSED", func(t *testing.T) {
		// P-052's unearned cycle: MINT-STATE.json + a re-based manifest,
		// two commits, no ledger row moved, a full verify spent.
		v := Decide([]string{"MINT-STATE.json", "ledger-amendments.json"})
		if v.Earned {
			t.Fatal("a record-only diff earned a witness cycle")
		}
		line := v.Line()
		for _, want := range []string{"REFUSES", "MINT-STATE.json", "ledger-amendments.json", "ALREADY WITNESSED"} {
			if !strings.Contains(line, want) {
				t.Fatalf("refusal %q omits %q", line, want)
			}
		}
	})

	t.Run("the refusal is ACTIONABLE, not a wall", func(t *testing.T) {
		line := Decide([]string{"GATE-RUN.txt"}).Line()
		if !strings.Contains(line, "Fold these into the next work commit") {
			t.Fatalf("the refusal does not say what to do instead: %q", line)
		}
		// And it must not wear the evidence prefix a passing gate wears.
		if strings.HasPrefix(line, "check OK:") {
			t.Fatalf("a refusal claimed the evidence prefix: %q", line)
		}
	})

	t.Run("every record path is recognised, wherever the record lives", func(t *testing.T) {
		for _, p := range []string{
			"GATE-RUN.txt", "GATE-RUN.integration.txt", "GATE-RUN.ci.txt",
			"GATE-RUN.e2e-full.txt", "ledger-amendments.json", "MINT-STATE.json",
		} {
			if Decide([]string{p}).Earned {
				t.Errorf("%s counted as substantive — it is a record", p)
			}
		}
	})

	t.Run("ONE substantive path earns the cycle, however many records ride along", func(t *testing.T) {
		v := Decide([]string{"GATE-RUN.txt", "ledger-amendments.json", "internal/service/local_login_service.go"})
		if !v.Earned {
			t.Fatal("a source change did not earn a witness")
		}
		if len(v.Substantive) != 1 || v.Substantive[0] != "internal/service/local_login_service.go" {
			t.Fatalf("substantive = %v, want just the source file", v.Substantive)
		}
		if !strings.HasPrefix(v.Line(), "check OK: witness-earns EARNED") {
			t.Fatalf("an earned cycle must say so: %q", v.Line())
		}
	})

	t.Run("A RECORD-LOOKING NAME IN A DIRECTORY IS NOT A RECORD", func(t *testing.T) {
		// The disarming mistake: matching on the basename anywhere would let
		// internal/foo/GATE-RUN.txt — or a source file someone names
		// ledger-amendments.json inside a package — suppress a real cycle.
		for _, p := range []string{
			"internal/service/GATE-RUN.txt",
			"tools/x/ledger-amendments.json",
			"docs/MINT-STATE.json",
		} {
			if !Decide([]string{p}).Earned {
				t.Errorf("%s was treated as a record; only the repository-root records are", p)
			}
		}
	})

	t.Run("nothing changed is refused too, and says the tree is already witnessed", func(t *testing.T) {
		v := Decide(nil)
		if v.Earned {
			t.Fatal("an empty diff earned a cycle")
		}
		if !strings.Contains(v.Line(), "nothing has changed") || !strings.Contains(v.Line(), "ALREADY WITNESSED") {
			t.Fatalf("line = %q", v.Line())
		}
	})
}
