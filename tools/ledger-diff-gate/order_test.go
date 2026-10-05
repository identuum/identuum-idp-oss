package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OSS-LEDGER-ORDER (2026-10-05): the cycle after a witness opens with the
// ledger rebase, alone. Each case is a real git history driven through run(),
// the gate's own entry point, with a fake rulefloor that answers "same".

func fakeRulefloor(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rulefloor")
	doc := `{"schema_version":"rulefloor.ledger-diff.v1","status":"same","rules":[],"total_rule_changes":0,"truncated":false}`
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho '"+doc+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFile(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// commitPaths writes each named file (the manifest gets base) and commits them.
func commitPaths(t *testing.T, dir, subject, base string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if p == "ledger-amendments.json" {
			writeFile(t, dir, p, manifestJSON(base, ""))
		} else {
			writeFile(t, dir, p, []byte(subject+"\n"))
		}
		git(t, dir, "add", p)
	}
	git(t, dir, "commit", "-q", "-m", subject)
}

// orderFixture: a history whose cycle before the witness w1 SLIPPED (a work
// commit before its rebase) — older history the gate must not judge.
func orderFixture(t *testing.T) (dir, w1 string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	commitPaths(t, dir, "work: start", strings.Repeat("0", 40), "a.txt", "ledger-amendments.json")
	w0 := gitCommit(t, dir, WitnessSubjectPrefix+"start")
	commitPaths(t, dir, "work: a passenger before the rebase", "", "a.txt")
	commitPaths(t, dir, "ledger: rebase on w0", w0, "ledger-amendments.json")
	return dir, gitCommit(t, dir, WitnessSubjectPrefix+"one")
}

func gate(t *testing.T, dir string) error {
	t.Helper()
	return run(filepath.Join(dir, "ledger-amendments.json"), dir, fakeRulefloor(t), false)
}

func TestLedgerOrder_TheRebaseOpensTheCycleAlone(t *testing.T) {
	t.Run("rebase first and alone, then work: pass", func(t *testing.T) {
		dir, w1 := orderFixture(t)
		commitPaths(t, dir, "ledger: rebase on w1", w1, "ledger-amendments.json")
		commitPaths(t, dir, "work: one", "", "a.txt")
		if err := gate(t, dir); err != nil {
			t.Fatalf("want pass, got %v", err)
		}
	})
	t.Run("a passenger commit before the rebase: fail, naming both", func(t *testing.T) {
		dir, w1 := orderFixture(t)
		commitPaths(t, dir, "work: passenger", "", "a.txt")
		passenger := git(t, dir, "rev-parse", "--short=7", "HEAD")
		commitPaths(t, dir, "ledger: rebase on w1", w1, "ledger-amendments.json")
		rebase := git(t, dir, "rev-parse", "--short=7", "HEAD")
		err := gate(t, dir)
		if err == nil || !strings.Contains(err.Error(), passenger) || !strings.Contains(err.Error(), rebase) {
			t.Fatalf("want a failure naming %s and %s, got %v", passenger, rebase, err)
		}
		if strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), "make ledger-rebase") {
			t.Fatalf("want one line that says what to do, got %q", err)
		}
	})
	t.Run("rebase plus another file in one commit: fail, naming the file", func(t *testing.T) {
		dir, w1 := orderFixture(t)
		commitPaths(t, dir, "ledger: rebase on w1, crowded", w1, "ledger-amendments.json", "b.txt")
		err := gate(t, dir)
		if err == nil || !strings.Contains(err.Error(), "b.txt") {
			t.Fatalf("want a failure naming b.txt, got %v", err)
		}
	})
	t.Run("no ledger change and none owed (HEAD is the witness): pass", func(t *testing.T) {
		dir, _ := orderFixture(t)
		if err := gate(t, dir); err != nil {
			t.Fatalf("want pass, got %v", err)
		}
	})
	t.Run("rebase owed but missing after other commits: fail on base_commit (kept)", func(t *testing.T) {
		dir, _ := orderFixture(t)
		commitPaths(t, dir, "work: one", "", "a.txt")
		commitPaths(t, dir, "work: two", "", "b.txt")
		err := gate(t, dir)
		if err == nil || !strings.Contains(err.Error(), "is not the previous accepted witness") {
			t.Fatalf("want the base_commit refusal, got %v", err)
		}
	})
}
