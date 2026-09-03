package main

// rebase_test.go — RULE: LEDGER-REBASE-DERIVES-BASE-1.
//
// The re-base is a convenience, and this file is what keeps it from becoming
// a bypass. Every subtest below is a way the convenience could have quietly
// weakened the gate: by editing what a human declared, by repairing a
// manifest that should have failed, by writing a base nobody measured, by
// making the derived base self-certifying, or by getting wired into `make
// verify` where it would rewrite the very thing verify is about to judge.

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const rebaseBase = "1111111111111111111111111111111111111111"
const rebaseNewBase = "2222222222222222222222222222222222222222"

func manifestJSON(baseSHA, changes string) []byte {
	return []byte(`{"schema_version":"ledger-amendments.v1","base_commit":"` + baseSHA + `","changes":[` + changes + `]}`)
}

// makefileRecipe returns the recipe lines of a Makefile target: everything
// indented under `name:` up to the first line that is neither blank nor
// indented.
func makefileRecipe(t *testing.T, src, name string) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, name+":") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("Makefile has no %s target", name)
	}
	var b strings.Builder
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if l != "" && !strings.HasPrefix(l, "\t") && !strings.HasPrefix(l, " ") {
			break
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// git runs one git command in the fixture repo and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitCommit makes one empty commit with the given subject and returns its SHA.
func gitCommit(t *testing.T, dir, subject string) string {
	t.Helper()
	git(t, dir, "commit", "-q", "--allow-empty", "-m", subject)
	return git(t, dir, "rev-parse", "HEAD")
}

// gitFixture builds a history shaped like the close ritual's: work, then a
// witness, with HEAD sitting on the witness — the state a slice starts from.
func gitFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	gitCommit(t, dir, "work: an earlier slice")
	gitCommit(t, dir, WitnessSubjectPrefix+"0000000")
	return dir
}

// RULE: LEDGER-REBASE-DERIVES-BASE-1
func TestRuleLedgerRebaseDerivesBase1_OnlyBaseWritten_InvalidRefused_DerivedBaseStillChecked(t *testing.T) {
	t.Run("declared changes and their reasons survive a re-base byte-for-byte", func(t *testing.T) {
		raw := manifestJSON(rebaseBase, declAdded+","+declSentence+","+declFingerprint)
		out, err := RebaseManifest(raw, rebaseNewBase)
		if err != nil {
			t.Fatalf("re-base: %v", err)
		}
		got, err := ParseManifest(out)
		if err != nil {
			t.Fatalf("re-based manifest does not parse: %v", err)
		}
		if got.BaseCommit != rebaseNewBase {
			t.Fatalf("base_commit = %s, want the measured %s", got.BaseCommit, rebaseNewBase)
		}
		want, err := ParseManifest(raw)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		if len(got.Changes) != len(want.Changes) {
			t.Fatalf("re-base changed the declaration count: %d -> %d", len(want.Changes), len(got.Changes))
		}
		for i, c := range want.Changes {
			g := got.Changes[i]
			if g.RuleID != c.RuleID || g.ChangeClass != c.ChangeClass ||
				g.AfterSentenceSHA256 != c.AfterSentenceSHA256 || g.Reason != c.Reason {
				t.Fatalf("re-base edited declaration %d: %+v -> %+v", i, c, g)
			}
		}
	})

	t.Run("an invalid manifest is REFUSED, never repaired", func(t *testing.T) {
		// A declaration with no reason: the gate refuses it, so the re-base
		// must refuse it too. Repairing it here would launder a manifest
		// that could never have been written by hand.
		noReason := `{"rule_id":"X-1","change_class":"rule_added"}`
		if _, err := RebaseManifest(manifestJSON(rebaseBase, noReason), rebaseNewBase); err == nil {
			t.Fatal("re-base accepted a manifest with an undeclared reason — it must refuse, not repair")
		}
		// And a manifest that is not even JSON.
		if _, err := RebaseManifest([]byte(`{"schema_version":`), rebaseNewBase); err == nil {
			t.Fatal("re-base accepted invalid JSON")
		}
	})

	t.Run("a base that was never measured is refused", func(t *testing.T) {
		for _, bad := range []string{"", "2359736", "not-a-sha", strings.Repeat("g", 40)} {
			if _, err := RebaseManifest(manifestJSON(rebaseBase, ""), bad); err == nil {
				t.Fatalf("re-base accepted %q as a base", bad)
			}
		}
	})

	t.Run("the DERIVED base is still checked: writing it does not certify it", func(t *testing.T) {
		// Re-based at one head, judged at another — the state that occurs
		// whenever a witness lands between the re-base and the verify.
		out, err := RebaseManifest(manifestJSON(rebaseBase, ""), rebaseNewBase)
		if err != nil {
			t.Fatalf("re-base: %v", err)
		}
		m, err := ParseManifest(out)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, err := Reconcile(m, sameDoc(), 0, base, "d"); err == nil {
			t.Fatal("a re-based manifest passed against a DIFFERENT measured witness — deriving became asserting")
		} else if !strings.Contains(err.Error(), "is not the previous accepted witness") {
			t.Fatalf("wrong refusal: %v", err)
		}
	})

	t.Run("re-basing is idempotent", func(t *testing.T) {
		once, err := RebaseManifest(manifestJSON(rebaseBase, declAdded), rebaseNewBase)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		twice, err := RebaseManifest(once, rebaseNewBase)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if string(once) != string(twice) {
			t.Fatalf("re-base is not idempotent:\n%s\n%s", once, twice)
		}
	})

	t.Run("an empty change list stays [] and never becomes null", func(t *testing.T) {
		out, err := RebaseManifest(manifestJSON(rebaseBase, ""), rebaseNewBase)
		if err != nil {
			t.Fatalf("re-base: %v", err)
		}
		var probe struct {
			Changes json.RawMessage `json:"changes"`
		}
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("re-based manifest is not JSON: %v", err)
		}
		if string(probe.Changes) != "[]" {
			t.Fatalf("changes rendered as %s, want []", probe.Changes)
		}
	})

	t.Run("the base derived BEFORE the commit is the base measured AFTER it", func(t *testing.T) {
		// The property the whole cadence rests on. The re-base runs while
		// the commit that will carry the manifest does not exist yet; the
		// gate runs once it does. If those two vantage points disagreed by
		// one commit, every re-base would write the SHA that fails.
		repo := gitFixture(t)

		// Derive now (HEAD is the witness W) …
		derived, err := newestWitness(repo, RevRebase)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		// … then land the commit that carries the manifest …
		work := gitCommit(t, repo, "work: the commit carrying the manifest")
		// … and let the gate measure from where it actually stands.
		measured, err := previousAcceptedWitness(repo)
		if err != nil {
			t.Fatalf("measure: %v", err)
		}
		if derived != measured {
			t.Fatalf("derived base %s but the gate measures %s at %s — every re-base would write the SHA that fails",
				derived, measured, work)
		}

		// And again one commit later: a second work commit does not move the
		// base, so a re-base run at any point in the same cycle agrees.
		derived2, err := newestWitness(repo, RevRebase)
		if err != nil {
			t.Fatalf("derive 2: %v", err)
		}
		gitCommit(t, repo, "work: a follow-up commit in the same cycle")
		measured2, err := previousAcceptedWitness(repo)
		if err != nil {
			t.Fatalf("measure 2: %v", err)
		}
		if derived2 != measured2 || derived2 != derived {
			t.Fatalf("the base moved inside one cycle: derived %s/%s, measured %s", derived, derived2, measured2)
		}
	})

	t.Run("make verify never re-bases the manifest it is about to judge", func(t *testing.T) {
		src, err := os.ReadFile("../../Makefile")
		if err != nil {
			t.Fatalf("read Makefile: %v", err)
		}
		makefile := string(src)

		verify := makefileRecipe(t, makefile, "verify")
		if !strings.Contains(verify, "ledger-diff-gate=") {
			t.Fatal("verify no longer runs ledger-diff-gate at all")
		}
		if strings.Contains(verify, "rebase") {
			t.Fatalf("the verify plan mentions a re-base — verify must judge the manifest, never write it:\n%s", verify)
		}
		gate := makefileRecipe(t, makefile, "ledger-diff-gate")
		if strings.Contains(gate, "-rebase") {
			t.Fatalf("the ledger-diff-gate target passes -rebase:\n%s", gate)
		}
		rebase := makefileRecipe(t, makefile, "ledger-rebase")
		if !strings.Contains(rebase, "--rebase") {
			t.Fatalf("the ledger-rebase target does not pass --rebase:\n%s", rebase)
		}
		// The flag exists in exactly one recipe: the deliberate one.
		if n := strings.Count(makefile, "--rebase"); n != 1 {
			t.Fatalf("--rebase appears %d times in the Makefile, want exactly 1 (the ledger-rebase target)", n)
		}
	})
}
