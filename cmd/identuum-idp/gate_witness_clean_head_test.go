package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE-STALE-WITNESS (2026-09-01): a slice report claimed "gate-witness minted
// LAST at clean HEAD" while the record committed inside that very commit read
// `repo-head: 9bec8d4 (dirty)` — minted BEFORE the commit, on a dirty tree.
// check passed anyway, because it verified only the content digest;
// repo-head was information, not a claim under test.
//
// This pins the strict semantics of scripts/gate-witness.sh (the vendored
// copy this repo's `make verify` actually runs; --sync-check holds it
// byte-identical to the wiki master):
//
//   - a record minted on a DIRTY tree fails check;
//   - a record naming any commit but the current clean HEAD fails check,
//     with exactly one allowance — HEAD being the record's own witness
//     commit (direct child, record file the only change);
//   - a record pinning a sibling repo (the two-repo witness) fails check
//     when that sibling moved.
//
// RULE: WITNESS-CLEAN-HEAD-1
func TestGateWitness_RecordMustNameTheCurrentCleanHead(t *testing.T) {
	script, err := filepath.Abs("../../scripts/gate-witness.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("vendored gate-witness.sh missing: %v", err)
	}

	// THE-RED-CI (run 33854648164): this test exercises gate-witness's DEFAULT
	// digest tie, and it inherited the caller's environment. CI exports
	// GATE_WITNESS_TIE=commit for the whole `make ci-verify` step, so in CI —
	// and only in CI — finalize wrote a commit tie instead, `check` failed
	// with "commit-tied but finalized on a dirty tree" rather than
	// "DIRTY-MINT", and the assertion below reported the right refusal for the
	// wrong reason. Green here, red there, for four runs nobody read.
	//
	// The child now gets an environment with every GATE_WITNESS_* steering
	// variable REMOVED, so the test measures the script's default behaviour no
	// matter what the caller has set. Reproduced before the fix with
	// `GATE_WITNESS_TIE=commit go test -run …` — byte-identical to the CI log.
	hermeticEnv := func() []string {
		out := make([]string, 0, len(os.Environ()))
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "GATE_WITNESS_") {
				continue
			}
			out = append(out, kv)
		}
		return out
	}()
	sh := func(t *testing.T, dir string, name string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = hermeticEnv
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out), code
	}
	git := func(t *testing.T, dir string, args ...string) {
		t.Helper()
		full := append([]string{"-c", "user.name=t", "-c", "user.email=t@local", "-c", "commit.gpgsign=false"}, args...)
		if out, code := sh(t, dir, "git", full...); code != 0 {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	newRepo := func(t *testing.T, dir string) {
		t.Helper()
		git(t, dir, "init", "-q", ".")
		if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("alpha\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, dir, "add", "f.txt")
		git(t, dir, "commit", "-qm", "base")
	}

	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	newRepo(t, repo)

	// ── DIRTY MINT FAILS: the exact shape the false report hid ──
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("alpha\ndrift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "bash", script, "run", "GATE-RUN.txt", "t gate", "a=true")
	out, code := sh(t, repo, "bash", script, "check", ".", "GATE-RUN.txt")
	if code == 0 {
		t.Fatal("a record minted on a DIRTY tree passed check — the false 'minted at clean HEAD' report is reproducible again")
	}
	if !strings.Contains(out, "DIRTY-MINT") {
		t.Fatalf("dirty mint failed for the wrong reason:\n%s", out)
	}
	git(t, repo, "checkout", "-q", "--", "f.txt")

	// ── CLEAN MINT PASSES, pre- and post- its own witness commit ──
	sh(t, repo, "bash", script, "run", "GATE-RUN.txt", "t gate", "a=true")
	if out, code := sh(t, repo, "bash", script, "check", ".", "GATE-RUN.txt"); code != 0 {
		t.Fatalf("a clean-HEAD mint failed check before its witness commit:\n%s", out)
	}
	git(t, repo, "add", "GATE-RUN.txt")
	git(t, repo, "commit", "-qm", "witness")
	if out, code := sh(t, repo, "bash", script, "check", ".", "GATE-RUN.txt"); code != 0 {
		t.Fatalf("the witness commit (record only, direct child) failed check:\n%s", out)
	}

	// ── HEAD MOVING BEYOND THE WITNESS COMMIT FAILS, even content-neutrally ──
	git(t, repo, "commit", "-qm", "later", "--allow-empty")
	out, code = sh(t, repo, "bash", script, "check", ".", "GATE-RUN.txt")
	if code == 0 {
		t.Fatal("HEAD moved beyond the witness commit and check still passed")
	}
	if !strings.Contains(out, "STALE-HEAD") {
		t.Fatalf("moved HEAD failed for the wrong reason:\n%s", out)
	}

	// ── THE TWO-REPO WITNESS: the pinned sibling moving fails check ──
	main2 := filepath.Join(root, "main2")
	sib := filepath.Join(root, "identuum-idp-oss")
	for _, d := range []string{main2, sib} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		newRepo(t, d)
	}
	cmd := exec.Command("bash", script, "run", "GATE-RUN.txt", "t xrepo gate", "a=true")
	cmd.Dir = main2
	// hermeticEnv, not os.Environ(): this case declares the ONE gate-witness
	// variable it wants and must not inherit CI's GATE_WITNESS_TIE=commit,
	// which would tie the record by commit and fail the check below for a
	// reason this case is not about (THE-RED-CI, run 33854648164).
	cmd.Env = append(hermeticEnv, "GATE_WITNESS_XREPO=identuum-idp-oss=../identuum-idp-oss")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("xrepo mint failed: %v\n%s", err, out)
	}
	rec, err := os.ReadFile(filepath.Join(main2, "GATE-RUN.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rec), "xrepo: identuum-idp-oss head=") {
		t.Fatal("the record carries no sibling pin — the two-repo witness is gone")
	}
	// The first live two-repo mint recorded tree=sha256:EMPTY-TREE — an
	// absolute exclusion path broke git's pathspec, both sides computed the
	// same empty value, and the digest comparison had no teeth. The pin must
	// be a real content hash.
	if !regexp.MustCompile(`(?m)^xrepo: identuum-idp-oss head=\S+ tree=sha256:[0-9a-f]{64}$`).Match(rec) {
		t.Fatalf("the sibling pin's digest is not a real sha256 — the EMPTY-TREE regression is back:\n%s", rec)
	}
	if out, code := sh(t, main2, "bash", script, "check", ".", "GATE-RUN.txt"); code != 0 {
		t.Fatalf("a fresh two-repo record failed check:\n%s", out)
	}
	git(t, sib, "commit", "-qm", "sibling moved", "--allow-empty")
	out, code = sh(t, main2, "bash", script, "check", ".", "GATE-RUN.txt")
	if code == 0 {
		t.Fatal("the pinned sibling moved and check still passed — the gate cannot say which idp-oss it exercised")
	}
	if !strings.Contains(out, "STALE-XREPO") {
		t.Fatalf("moved sibling failed for the wrong reason:\n%s", out)
	}
}
