package main

// judge_test.go — RULE: CI-RECORD-HONEST-1.
//
// The failure this gate exists to prevent is a record that READS like CI
// evidence without being it: a stray local run left in the working tree, a
// committed record with no provenance, a half-dead run, a record for a
// commit this checkout never had — or an absence that quietly passes as
// though CI had run.
//
// The untracked case is the one that actually happened. The first version of
// this gate accepted a green, commit-tied GATE-RUN.ci.txt sitting in the
// working tree from 2026-08-28, 138 commits behind HEAD, written by a LOCAL
// `make ci-verify` into the same gitignored path with the same `gate:`
// label. Nothing in the bytes distinguished it from a downloaded artifact.

import (
	"strings"
	"testing"
)

const ciCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func ciRecord() string {
	return strings.Join([]string{
		"gate: identuum-idp-oss make ci-verify",
		"plan: tool-versions repo-green rulefloor-check",
		"target: tool-versions exit=0",
		"target: repo-green exit=0",
		"target: rulefloor-check exit=0",
		"result: green",
		"tree: commit=" + ciCommit,
		"ci-run: https://github.com/o/r/actions/runs/123 attempt=1",
	}, "\n") + "\n"
}

// judged parses a record and marks it COMMITTED — the state that makes it a
// claim at all — then judges it against the given ancestry.
func judged(raw string, a Ancestry) (string, bool) {
	r := ParseRecord([]byte(raw))
	r.Tracked = true
	return Judge(r, a)
}

func onAncestry() Ancestry { return Ancestry{Known: true, IsAncestor: true, Behind: 0} }

// RULE: CI-RECORD-HONEST-1
func TestRuleCIRecordHonest1_AbsenceSaysSo_UntrackedIsNoClaim_PresentMustBeProvenanced(t *testing.T) {
	t.Run("ABSENT: passes, and the line says nothing is evidenced", func(t *testing.T) {
		summary, ok := Judge(Record{Present: false}, Ancestry{})
		if !ok {
			t.Fatalf("absence must not fail the build: %s", summary)
		}
		if !strings.HasPrefix(summary, "check OK:") {
			t.Fatalf("evidence pattern lost: %q", summary)
		}
		for _, want := range []string{"NO CI RECORD", "declared, unrun"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("absence line %q does not say %q — silence that reads like a pass is the bug", summary, want)
			}
		}
	})

	t.Run("UNTRACKED: a stray local ci-verify record is NOT a CI claim", func(t *testing.T) {
		// The live regression: green, commit-tied, and meaningless.
		r := ParseRecord([]byte(ciRecord()))
		r.Tracked = false
		summary, ok := Judge(r, Ancestry{Known: true, IsAncestor: true, Behind: 138})
		if !ok {
			t.Fatalf("an untracked record must not fail the build, only fail to claim: %s", summary)
		}
		for _, want := range []string{"NO CI CLAIM", "UNTRACKED", "declared, unrun"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("untracked line %q does not say %q", summary, want)
			}
		}
	})

	t.Run("committed WITHOUT provenance FAILS — nothing distinguishes it from a local run", func(t *testing.T) {
		noRun := strings.Replace(ciRecord(), "ci-run: https://github.com/o/r/actions/runs/123 attempt=1\n", "", 1)
		summary, ok := judged(noRun, onAncestry())
		if ok {
			t.Fatalf("a committed record with no ci-run provenance passed: %s", summary)
		}
		if !strings.Contains(summary, "ci-run") {
			t.Fatalf("failure does not name the missing provenance: %q", summary)
		}
	})

	t.Run("a complete, green, provenanced, commit-tied record on our ancestry passes", func(t *testing.T) {
		summary, ok := judged(ciRecord(), onAncestry())
		if !ok {
			t.Fatalf("a good CI record must pass: %s", summary)
		}
		for _, want := range []string{"green", "3 planned target(s)", "ties commit aaaaaaa", "at HEAD", "runs/123"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("evidence line %q omits %q", summary, want)
			}
		}
	})

	t.Run("a LOCAL record wearing a CI name FAILS (digest tie, not commit tie)", func(t *testing.T) {
		local := strings.Replace(ciRecord(), "tree: commit="+ciCommit, "tree: sha256=deadbeef", 1)
		summary, ok := judged(local, onAncestry())
		if ok {
			t.Fatalf("a digest-tied record passed as a CI witness: %s", summary)
		}
		if !strings.Contains(summary, "cannot witness CI") {
			t.Fatalf("failure does not name the reason: %q", summary)
		}
	})

	t.Run("a red record FAILS", func(t *testing.T) {
		red := strings.Replace(ciRecord(), "result: green", "result: red", 1)
		if summary, ok := judged(red, onAncestry()); ok {
			t.Fatalf("a red CI record passed: %s", summary)
		}
	})

	t.Run("an INCOMPLETE record FAILS — a planned target that never ran is not a pass", func(t *testing.T) {
		half := strings.Replace(ciRecord(), "target: rulefloor-check exit=0\n", "", 1)
		summary, ok := judged(half, onAncestry())
		if ok {
			t.Fatalf("a half-dead run passed: %s", summary)
		}
		if !strings.Contains(summary, "rulefloor-check (never recorded)") {
			t.Fatalf("failure does not name the unrun target: %q", summary)
		}
	})

	t.Run("a planned target that FAILED is named, not averaged away", func(t *testing.T) {
		failed := strings.Replace(ciRecord(), "target: repo-green exit=0", "target: repo-green exit=2", 1)
		summary, ok := judged(failed, onAncestry())
		if ok {
			t.Fatalf("a record with a failing target passed: %s", summary)
		}
		if !strings.Contains(summary, "repo-green (exit=2)") {
			t.Fatalf("failure does not name the failing target: %q", summary)
		}
	})

	t.Run("an EMPTY plan FAILS — a run that planned nothing proves nothing", func(t *testing.T) {
		empty := strings.Replace(ciRecord(), "plan: tool-versions repo-green rulefloor-check", "plan: ", 1)
		if summary, ok := judged(empty, onAncestry()); ok {
			t.Fatalf("an empty plan passed: %s", summary)
		}
	})

	t.Run("dirty-at-finalize FAILS — the commit named is not the tree that ran", func(t *testing.T) {
		dirty := strings.Replace(ciRecord(), "tree: commit="+ciCommit,
			"tree: commit="+ciCommit+" (dirty-at-finalize)", 1)
		summary, ok := judged(dirty, onAncestry())
		if ok {
			t.Fatalf("a dirty CI record passed: %s", summary)
		}
		if !strings.Contains(summary, "DIRTY") {
			t.Fatalf("failure does not name dirtiness: %q", summary)
		}
	})

	t.Run("a commit this repository does not contain FAILS", func(t *testing.T) {
		summary, ok := judged(ciRecord(), Ancestry{Known: false})
		if ok {
			t.Fatalf("a record for an unknown commit passed: %s", summary)
		}
		if !strings.Contains(summary, "not in this repository") {
			t.Fatalf("failure does not name the reason: %q", summary)
		}
	})

	t.Run("a commit off HEAD's ancestry FAILS", func(t *testing.T) {
		summary, ok := judged(ciRecord(), Ancestry{Known: true, IsAncestor: false})
		if ok {
			t.Fatalf("a record from another line of history passed: %s", summary)
		}
		if !strings.Contains(summary, "different line of history") {
			t.Fatalf("failure does not name the reason: %q", summary)
		}
	})

	t.Run("BEHIND is reported, never failed — and the line says which tree the claim covers", func(t *testing.T) {
		summary, ok := judged(ciRecord(), Ancestry{Known: true, IsAncestor: true, Behind: 22})
		if !ok {
			t.Fatalf("a behind-but-valid CI record must pass — failing it would push people to delete it: %s", summary)
		}
		for _, want := range []string{"22 commit(s) behind HEAD", "not this one"} {
			if !strings.Contains(summary, want) {
				t.Fatalf("evidence line %q does not disclose the distance (%q)", summary, want)
			}
		}
	})
}
