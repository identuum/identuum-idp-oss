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

// THE-CONFORMANCE-HARNESS (2026-09-01). Two invariants of
// conformance/run.sh worth pinning, proven through its committed test seams
// (CONFORMANCE_STUB_STACK / CONFORMANCE_STUB_PLAN / CONFORMANCE_STUB_TEARDOWN
// plus a recording `docker` shim on PATH — no real docker, no network):
//
//  1. GUARANTEED TEARDOWN: `down --volumes` on the identuum-conformance
//     project fires on success, on failure, AND on interrupt mid-plan. A
//     harness that leaves two stacks running after Ctrl-C is exactly the
//     debris the owner ruling forbids.
//  2. FLOOR SEMANTICS: an expected failure that PASSES fails the run. The
//     basic plan's recorded abort (mandatory PKCE; the suite's own
//     expected-failures format cannot express an interrupted module) is a
//     floor — a run where that plan COMPLETES must exit nonzero until the
//     baseline is re-recorded deliberately.
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
	abortLine := ""
	{
		raw, err := os.ReadFile(filepath.Join(repo, "conformance", "expected-basic-abort.txt"))
		if err != nil {
			t.Fatalf("expected-basic-abort.txt missing: %v", err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				abortLine = l
				break
			}
		}
	}
	if abortLine == "" {
		t.Fatal("expected-basic-abort.txt carries no abort signature line")
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

	// ── 1a. SUCCESS path: both plans green-against-floor -> exit 0, and the
	// teardown still ran down --volumes on the project ──
	code, calls := runHarness(t, perPlan("echo '"+abortLine+"'; exit 1"), false)
	if code != 0 {
		t.Fatalf("green-against-floor run exited %d, want 0 (the recorded abort matched)", code)
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

	// ── 2. FLOOR: the basic plan COMPLETING (exit 0) must FAIL the run —
	// an expected failure that passes is floor movement ──
	code, calls = runHarness(t, perPlan("echo 'all modules passed'; exit 0"), false)
	if code == 0 {
		t.Fatal("the recorded basic-plan abort no longer happened and the harness still exited 0 — the floor moved silently")
	}
	if !strings.Contains(calls, "down --volumes") {
		t.Fatalf("teardown missing on the floor-moved path; docker calls:\n%s", calls)
	}

	// ── 2b. a DIFFERENT abort (neither the recorded one nor completion)
	// also fails ──
	code, _ = runHarness(t, perPlan("echo 'some other explosion'; exit 1"), false)
	if code == 0 {
		t.Fatal("a basic-plan failure DIFFERENT from the recorded abort passed as green")
	}
}
