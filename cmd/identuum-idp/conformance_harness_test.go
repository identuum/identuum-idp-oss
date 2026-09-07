package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// THE-CONFORMANCE-HARNESS; floor re-recorded by THE-PKCE-DECISION and again
// by THE-SECOND-LOGIN (2026-09-01). Two invariants of conformance/run.sh
// worth pinning, proven through its committed test seams
// (CONFORMANCE_STUB_STACK / CONFORMANCE_STUB_PLAN / CONFORMANCE_STUB_TEARDOWN
// plus a recording `docker` shim on PATH — no real docker, no network):
//
//  1. GUARANTEED TEARDOWN: `down --volumes` on the identuum-conformance
//     project fires on success, on failure, AND on interrupt mid-plan. A
//     harness that leaves two stacks running after Ctrl-C is exactly the
//     debris the owner ruling forbids.
//  2. FLOOR SEMANTICS with the incomplete-module floor EMPTY: the basic plan
//     is green ONLY when run-test-plan itself exits 0 against the committed
//     expected-failures/expected-skips files. A nonzero plan fails; so does
//     a plan that reports an "Incomplete test modules:" block, because no
//     recorded set exists for it to equal. (When the floor carries module
//     lines, the exact-set-equality branch re-engages — THE-PKCE-DECISION's
//     contract; this test pins the current, empty-floor mode.)
//
// RULE: CONFORMANCE-FLOOR-1
func TestConformanceHarness_TeardownAlwaysAndFloorNeverSilentlyMoves(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(repo, "conformance", "run.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("conformance/run.sh missing: %v", err)
	}
	{
		raw, err := os.ReadFile(filepath.Join(repo, "conformance", "expected-basic-incomplete.txt"))
		if err != nil {
			t.Fatalf("expected-basic-incomplete.txt missing: %v", err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				t.Fatalf("expected-basic-incomplete.txt carries module line %q — this test pins the EMPTY-floor contract; if a stall was re-recorded deliberately, rewrite the floor cases for set equality", l)
			}
		}
	}

	// A recording `docker` shim: every invocation is appended to a log the
	// assertions read back.
	shimDir := t.TempDir()
	dockerLog := filepath.Join(shimDir, "docker-calls.log")
	shim := "#!/usr/bin/env bash\necho \"$@\" >> " + dockerLog + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shimDir, "docker"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}

	runHarness := func(t *testing.T, stubPlan string, interrupt bool) (int, string, string) {
		t.Helper()
		_ = os.Remove(dockerLog)
		cmd := exec.Command("bash", script)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"PATH="+shimDir+":"+os.Getenv("PATH"),
			"CONFORMANCE_STUB_STACK=1",
			"CONFORMANCE_STUB_TEARDOWN=1",
			"CONFORMANCE_STUB_PLAN="+stubPlan,
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		outFile, err := os.CreateTemp(shimDir, "harness-out")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = outFile, outFile
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if interrupt {
			time.Sleep(1500 * time.Millisecond)
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		}
		waitErr := cmd.Wait()
		code := 0
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if waitErr != nil {
			code = -1
		}
		calls, _ := os.ReadFile(dockerLog)
		_ = outFile.Close()
		printed, _ := os.ReadFile(outFile.Name())
		return code, string(calls), string(printed)
	}

	// The stub receives the plan name as $1: the config plan passes clean,
	// the basic plan produces whatever verdict the case under test needs.
	perPlan := func(basicScript string) string {
		return `case "$1" in *config*) exit 0;; *) ` + basicScript + `;; esac`
	}

	// ── 1a. SUCCESS path: both plans exit 0 -> exit 0, and the teardown
	// still ran down --volumes on the project ──
	code, calls, _ := runHarness(t, perPlan("echo 'all modules ran to completion'; exit 0"), false)
	if code != 0 {
		t.Fatalf("green run exited %d, want 0 (both plans clean against the committed floor)", code)
	}
	if !strings.Contains(calls, "compose -p identuum-conformance") || !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown did not run 'down --volumes' on the isolated project after success; docker calls:\n%s", calls)
	}

	// ── 1b. INTERRUPT mid-plan: teardown STILL fires ──
	code, calls, _ = runHarness(t, "sleep 30", true)
	if code == 0 {
		t.Fatal("an interrupted run exited 0")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("Ctrl-C mid-plan did NOT tear the stacks down; docker calls:\n%s", calls)
	}

	// ── 2a. FLOOR: a nonzero basic plan (unexpected condition failures)
	// fails the run — the expected files are the only floor ──
	code, calls, _ = runHarness(t, perPlan("echo '** Exiting with failure - some test modules have unexpected condition failures/warnings **'; exit 1"), false)
	if code == 0 {
		t.Fatal("a basic plan with unexpected condition failures passed as green")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown missing on the failing path; docker calls:\n%s", calls)
	}

	// ── 2b. FLOOR: a stalled module (an "Incomplete test modules:" block)
	// fails while the incomplete floor is EMPTY — no recorded set to equal,
	// so a stall can never pass silently ──
	code, _, _ = runHarness(t, perPlan("echo 'Incomplete test modules:'; echo '  oidcc-prompt-login Stub1 (status: WAITING)'; exit 1"), false)
	if code == 0 {
		t.Fatal("a stalled module passed as green against an EMPTY incomplete floor — the re-auth finding could silently return")
	}

	// ── 3. EVIDENCE ON RED (THE-HONEST-HARNESS-AND-THE-PUSH, 2026-09-07): the
	// only proof of WHAT failed is the suite's exported module logs, and they
	// live in the throwaway work dir the teardown deletes — so a red run used
	// to end with a verdict and nothing to read. A red run now KEEPS the
	// export under conformance/.evidence/<UTC stamp>/ and prints the path; a
	// green run keeps nothing, because kept evidence nobody needs is debris.
	evidenceDir := filepath.Join(repo, "conformance", ".evidence")
	names := func() map[string]bool {
		seen := map[string]bool{}
		entries, err := os.ReadDir(evidenceDir)
		if err != nil {
			return seen
		}
		for _, e := range entries {
			seen[e.Name()] = true
		}
		return seen
	}
	addedSince := func(before map[string]bool) []string {
		var added []string
		for name := range names() {
			if !before[name] {
				added = append(added, name)
			}
		}
		return added
	}
	base := names()
	t.Cleanup(func() { // this test leaves no evidence of its own behind
		for _, name := range addedSince(base) {
			_ = os.RemoveAll(filepath.Join(evidenceDir, name))
		}
		_ = os.Remove(evidenceDir) // succeeds only if it is now empty
	})
	// The stub writes what run-test-plan.py's --export-dir writes. It reaches
	// the work dir through CONFORMANCE_TLS_DIR, the seam the harness already
	// exports; no new seam is added for the test.
	exporting := func(exit string) string {
		return perPlan(`mkdir -p "$CONFORMANCE_TLS_DIR/export"; echo '{}' > "$CONFORMANCE_TLS_DIR/export/oidcc-stub-module.json"; ` + exit)
	}

	before := names()
	code, _, printed := runHarness(t, exporting("exit 1"), false)
	if code == 0 {
		t.Fatal("the red case exited 0")
	}
	kept := addedSince(before)
	if len(kept) != 1 {
		t.Fatalf("a red run kept %d evidence directories, want exactly 1; output:\n%s", len(kept), printed)
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, kept[0], "export", "oidcc-stub-module.json")); err != nil {
		t.Fatalf("the exported module logs went to the trash with the work dir: %v", err)
	}
	if !strings.Contains(printed, "EVIDENCE KEPT") || !strings.Contains(printed, kept[0]) {
		t.Fatalf("a red run kept evidence without printing where; output:\n%s", printed)
	}

	before = names()
	code, _, printed = runHarness(t, exporting("exit 0"), false)
	if code != 0 {
		t.Fatalf("the green case exited %d, want 0", code)
	}
	if added := addedSince(before); len(added) != 0 {
		t.Fatalf("a GREEN run kept evidence %v — only a red run keeps anything", added)
	}
	if strings.Contains(printed, "EVIDENCE KEPT") {
		t.Fatalf("a green run announced kept evidence; output:\n%s", printed)
	}

	// ── 4. EXACT NAMES: every verdict line names the plan the way the suite
	// does, so a line can be pasted into a report or a certification thread
	// and still say WHICH plan it is about.
	if !strings.Contains(printed, "oidcc-basic-certification-test-plan green against the committed expected-failures floor") {
		t.Fatalf("the green verdict does not name the plan exactly; output:\n%s", printed)
	}
	for _, vague := range []string{"basic plan", "config plan"} {
		if strings.Contains(printed, vague) {
			t.Errorf("output still says %q instead of the plan's exact name; output:\n%s", vague, printed)
		}
	}
}
