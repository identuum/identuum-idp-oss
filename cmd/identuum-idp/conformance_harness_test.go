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

	// ── 1a. SUCCESS path: both plans exit 0 -> exit 0, and the teardown
	// still ran down --volumes on the project ──
	code, calls := runHarness(t, perPlan("echo 'all modules ran to completion'; exit 0"), false)
	if code != 0 {
		t.Fatalf("green run exited %d, want 0 (both plans clean against the committed floor)", code)
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

	// ── 2a. FLOOR: a nonzero basic plan (unexpected condition failures)
	// fails the run — the expected files are the only floor ──
	code, calls = runHarness(t, perPlan("echo '** Exiting with failure - some test modules have unexpected condition failures/warnings **'; exit 1"), false)
	if code == 0 {
		t.Fatal("a basic plan with unexpected condition failures passed as green")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown missing on the failing path; docker calls:\n%s", calls)
	}

	// ── 2b. FLOOR: a stalled module (an "Incomplete test modules:" block)
	// fails while the incomplete floor is EMPTY — no recorded set to equal,
	// so a stall can never pass silently ──
	code, _ = runHarness(t, perPlan("echo 'Incomplete test modules:'; echo '  oidcc-prompt-login Stub1 (status: WAITING)'; exit 1"), false)
	if code == 0 {
		t.Fatal("a stalled module passed as green against an EMPTY incomplete floor — the re-auth finding could silently return")
	}
}
