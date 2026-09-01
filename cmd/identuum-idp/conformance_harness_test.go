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

// THE-CONFORMANCE-HARNESS, floor re-recorded by THE-PKCE-DECISION
// (2026-09-01). Two invariants of conformance/run.sh worth pinning, proven
// through its committed test seams (CONFORMANCE_STUB_STACK /
// CONFORMANCE_STUB_PLAN / CONFORMANCE_STUB_TEARDOWN plus a recording
// `docker` shim on PATH — no real docker, no network):
//
//  1. GUARANTEED TEARDOWN: `down --volumes` on the identuum-conformance
//     project fires on success, on failure, AND on interrupt mid-plan. A
//     harness that leaves two stacks running after Ctrl-C is exactly the
//     debris the owner ruling forbids.
//  2. FLOOR SEMANTICS: the basic plan is green ONLY when its
//     incomplete-module set EQUALS conformance/expected-basic-incomplete.txt
//     exactly (the re-auth finding: prompt=login / max_age=1 stall in
//     WAITING, which the suite's expected-failures format cannot express)
//     and no other failure marker fired. A plan that IMPROVES (the recorded
//     modules complete, exit 0) must ALSO fail — the floor moves only by
//     deliberate re-recording. So must a plan whose incompletes differ, and
//     one with unexpected condition failures.
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
	var incompleteModules []string
	{
		raw, err := os.ReadFile(filepath.Join(repo, "conformance", "expected-basic-incomplete.txt"))
		if err != nil {
			t.Fatalf("expected-basic-incomplete.txt missing: %v", err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				incompleteModules = append(incompleteModules, strings.TrimSpace(l))
			}
		}
	}
	if len(incompleteModules) == 0 {
		t.Fatal("expected-basic-incomplete.txt carries no module lines — if the floor was retired, rewrite this test for the plan-completes contract")
	}

	// A recording `docker` shim: every invocation is appended to a log the
	// assertions read back.
	shimDir := t.TempDir()
	dockerLog := filepath.Join(shimDir, "docker-calls.log")
	shim := "#!/usr/bin/env bash\necho \"$@\" >> " + dockerLog + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(shimDir, "docker"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}

	runHarness := func(t *testing.T, stubPlan string, interrupt bool) (int, string) {
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
		out, _ := os.CreateTemp(shimDir, "harness-out")
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if interrupt {
			time.Sleep(1500 * time.Millisecond)
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		}
		err := cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		calls, _ := os.ReadFile(dockerLog)
		return code, string(calls)
	}

	// The stub receives the plan name as $1: the config plan passes clean,
	// the basic plan produces whatever verdict the case under test needs.
	perPlan := func(basicScript string) string {
		return `case "$1" in *config*) exit 0;; *) ` + basicScript + `;; esac`
	}
	// incompleteBlock emits the exact "Incomplete test modules:" block
	// run-test-plan prints for the RECORDED floor; recordedIncomplete
	// additionally exits nonzero the way run-test-plan does.
	incompleteBlock := "echo 'Incomplete test modules:'"
	for _, m := range incompleteModules {
		incompleteBlock += "; echo '  " + m + " StubModuleId000 (status: WAITING)'"
	}
	recordedIncomplete := incompleteBlock + "; exit 1"

	// ── 1a. SUCCESS path: incompletes match the recorded floor exactly ->
	// exit 0, and the teardown still ran down --volumes on the project ──
	code, calls := runHarness(t, perPlan(recordedIncomplete), false)
	if code != 0 {
		t.Fatalf("green-against-floor run exited %d, want 0 (the recorded incomplete set matched)", code)
	}
	if !strings.Contains(calls, "compose -p identuum-conformance") || !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown did not run 'down --volumes' on the isolated project after success; docker calls:\n%s", calls)
	}

	// ── 1b. INTERRUPT mid-plan: teardown STILL fires ──
	code, calls = runHarness(t, "sleep 30", true)
	if code == 0 {
		t.Fatal("an interrupted run exited 0")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("Ctrl-C mid-plan did NOT tear the stacks down; docker calls:\n%s", calls)
	}

	// ── 2a. FLOOR (improvement): the basic plan COMPLETING (exit 0) while
	// the incomplete floor is non-empty must FAIL the run ──
	code, calls = runHarness(t, perPlan("echo 'all modules passed'; exit 0"), false)
	if code == 0 {
		t.Fatal("the recorded incompletes no longer happened and the harness still exited 0 — the floor moved silently")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown missing on the floor-moved path; docker calls:\n%s", calls)
	}

	// ── 2b. FLOOR (different incompletes): a nonzero run whose incomplete
	// set differs from the record also fails ──
	code, _ = runHarness(t, perPlan("echo 'Incomplete test modules:'; echo '  oidcc-some-other-module Stub1 (status: WAITING)'; exit 1"), false)
	if code == 0 {
		t.Fatal("a basic plan with DIFFERENT incomplete modules passed as green")
	}

	// ── 2c. FLOOR (extra damage): the recorded incompletes PLUS unexpected
	// condition failures also fails ──
	code, _ = runHarness(t, perPlan(incompleteBlock+"; echo '** Exiting with failure - some test modules have unexpected condition failures/warnings **'; exit 1"), false)
	if code == 0 {
		t.Fatal("recorded incompletes plus unexpected condition failures passed as green")
	}
}
