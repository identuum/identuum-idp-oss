package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// THE-CONFORMANCE-HARNESS; floor re-recorded by THE-PKCE-DECISION and again
// by THE-SECOND-LOGIN (2026-09-01). Two invariants of conformance/run.sh
// worth pinning, proven through its committed test seams
// (CONFORMANCE_STUB_STACK / CONFORMANCE_STUB_PLAN / CONFORMANCE_STUB_TEARDOWN
// plus a recording `docker` shim on PATH that models the engine ID, the
// context endpoint and the daemon mutex — no real docker, no network). The
// harness runs from a private copy of conformance/ whose one claim line points
// into the test's own directory, so the test never touches /tmp.
//
//  1. GUARANTEED TEARDOWN: the recorded teardown of the scratch-conformance
//     project fires on success, on failure, AND on interrupt mid-plan, and
//     releases the harness claim and the daemon mutex. A harness that leaves
//     two stacks running after Ctrl-C is exactly the debris the owner ruling
//     forbids. OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K1-K5): that teardown is no
//     longer a project-level `down --volumes` — it removes only what the run
//     recorded creating, by ID — the run takes the one harness claim and the
//     daemon mutex before any docker work, refuses a held claim and any
//     engine that is not this host's unix socket, and mounts no host path.
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

	// SPEC K1/K5, from the source: the project is scratch-prefixed, no
	// executable line runs a Compose `down` (or --remove-orphans), the TLS
	// sidecar mounts no host directory, and the built image is a scratch name.
	{
		src, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`(?m)^PROJECT="scratch-conformance"$`).Match(src) {
			t.Fatal(`conformance/run.sh does not set PROJECT="scratch-conformance"`)
		}
		if m := regexp.MustCompile(`(?m)^\s*(?:docker\s+)?compose\s[^#\n]*\b(down|--remove-orphans)\b`).Find(src); m != nil {
			t.Fatalf("conformance/run.sh still runs a project-level teardown: %q", m)
		}
		tls, err := os.ReadFile(filepath.Join(repo, "conformance", "compose.tls.yml"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(tls), "CONFORMANCE_TLS_DIR") || regexp.MustCompile(`(?m)^\s+volumes:`).Match(tls) {
			t.Fatal("compose.tls.yml mounts a host directory into the TLS sidecar")
		}
		app, err := os.ReadFile(filepath.Join(repo, "conformance", "compose.appliance.yml"))
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`(?m)^\s+image: scratch-conformance-idp:local$`).Match(app) {
			t.Fatal("compose.appliance.yml does not build the scratch image scratch-conformance-idp:local")
		}
	}

	// A private copy of conformance/: the one claim line points at this test's
	// directory (SPEC K2: the real path is fixed, never derived from TMPDIR).
	work := t.TempDir()
	lock := filepath.Join(work, "identuum-harness.lock")
	copyDir := filepath.Join(work, "repo", "conformance")
	if err := os.MkdirAll(copyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(repo, "conformance"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(repo, "conformance", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if e.Name() == "run.sh" {
			const line = "HARNESS_LOCK=/tmp/identuum-harness.lock\n"
			if strings.Count(string(raw), line) != 1 {
				t.Fatalf("run.sh does not declare the one fixed claim line %q", line)
			}
			raw = []byte(strings.Replace(string(raw), line, "HARNESS_LOCK="+lock+"\n", 1))
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(copyDir, e.Name()), raw, mode); err != nil {
			t.Fatal(err)
		}
	}
	script = filepath.Join(copyDir, "run.sh")

	// A recording `docker` shim: every invocation is appended to a log the
	// assertions read back. It answers the engine ID, a unix-socket context
	// endpoint and the mutex image, and holds the daemon mutex as a directory
	// created atomically, like the daemon's name reservation.
	shimDir := t.TempDir()
	dockerLog := filepath.Join(shimDir, "docker-calls.log")
	state := filepath.Join(shimDir, "state")
	shim := `#!/usr/bin/env bash
echo "$@" >> ` + dockerLog + `
S=` + state + `; mkdir -p "$S"
case "$1 $2" in
"context inspect") echo unix:///shim/docker.sock; exit 0 ;;
"image inspect") echo null; exit 0 ;;
"container create")
  owner=; for a in "$@"; do case "$a" in io.identuum.harness.mutex-owner=*) owner="${a#*=}" ;; esac; done
  mkdir "$S/mutex" 2>/dev/null || { echo "Conflict: the mutex name is in use" >&2; exit 1; }
  echo "$owner" > "$S/mutex/owner"; echo shim-mutex-id; exit 0 ;;
"container inspect") [ -d "$S/mutex" ] || exit 1; echo "shim-mutex-id $(cat "$S/mutex/owner") shim-engine"; exit 0 ;;
"container rm") rm -rf "$S/mutex"; exit 0 ;;
esac
[ "$1" = info ] && { echo shim-engine; exit 0; }
exit 0
`
	if err := os.WriteFile(filepath.Join(shimDir, "docker"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}

	released := func(t *testing.T, printed string) {
		t.Helper()
		if _, err := os.Stat(lock); !os.IsNotExist(err) {
			t.Fatalf("the harness claim %s was not released; output:\n%s", lock, printed)
		}
		if _, err := os.Stat(filepath.Join(state, "mutex")); !os.IsNotExist(err) {
			t.Fatalf("the daemon mutex was not released; output:\n%s", printed)
		}
	}
	noDown := func(t *testing.T, calls string) {
		t.Helper()
		if regexp.MustCompile(`(?m)\bcompose\b.*\b(down|--remove-orphans)\b`).MatchString(calls) {
			t.Fatalf("a project-level teardown ran; docker calls:\n%s", calls)
		}
	}

	runHarnessEnv := func(t *testing.T, stubPlan string, interrupt bool, extra ...string) (int, string, string) {
		t.Helper()
		_ = os.Remove(dockerLog)
		cmd := exec.Command("bash", script)
		cmd.Dir = filepath.Dir(copyDir)
		cmd.Env = append(append(os.Environ(),
			"PATH="+shimDir+":"+os.Getenv("PATH"),
			"CONFORMANCE_STUB_STACK=1",
			"CONFORMANCE_STUB_PLAN="+stubPlan,
		), extra...)
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
	runHarness := func(t *testing.T, stubPlan string, interrupt bool) (int, string, string) {
		t.Helper()
		return runHarnessEnv(t, stubPlan, interrupt)
	}

	// The stub receives the plan name as $1: the config plan passes clean,
	// the basic plan produces whatever verdict the case under test needs.
	perPlan := func(basicScript string) string {
		return `case "$1" in *config*) exit 0;; *) ` + basicScript + `;; esac`
	}

	const torn = "openid-conformance: teardown (project scratch-conformance: removed only what this run recorded creating"

	// ── 1a. SUCCESS path: both plans exit 0 -> exit 0, and the recorded
	// teardown still ran, with no down, and released the claim and mutex ──
	code, calls, printed := runHarness(t, perPlan("echo 'all modules ran to completion'; exit 0"), false)
	if code != 0 {
		t.Fatalf("green run exited %d, want 0 (both plans clean against the committed floor); output:\n%s", code, printed)
	}
	if !strings.Contains(printed, torn) {
		t.Fatalf("the recorded teardown did not run after success; output:\n%s", printed)
	}
	noDown(t, calls)
	released(t, printed)
	if !regexp.MustCompile(`container create --name identuum-harness-lock-engine .*io\.identuum\.harness\.kind=openid-conformance --label io\.identuum\.harness\.project=scratch-conformance --label io\.identuum\.harness\.ports=28443,28444,27113`).MatchString(calls) {
		t.Fatalf("the daemon mutex was not taken with this harness's kind, project and ports; docker calls:\n%s", calls)
	}
	if first := strings.SplitN(calls, "\n", 2)[0]; !strings.HasPrefix(first, "context inspect") {
		t.Fatalf("the first docker call is %q, not the endpoint resolution", first)
	}

	// ── 1b. INTERRUPT mid-plan: teardown STILL fires ──
	code, calls, printed = runHarness(t, "sleep 30", true)
	if code == 0 {
		t.Fatal("an interrupted run exited 0")
	}
	if !strings.Contains(printed, torn) {
		t.Fatalf("Ctrl-C mid-plan did NOT run the recorded teardown; output:\n%s", printed)
	}
	noDown(t, calls)
	released(t, printed)

	// ── 2a. FLOOR: a nonzero basic plan (unexpected condition failures)
	// fails the run — the expected files are the only floor ──
	code, calls, printed = runHarness(t, perPlan("echo '** Exiting with failure - some test modules have unexpected condition failures/warnings **'; exit 1"), false)
	if code == 0 {
		t.Fatal("a basic plan with unexpected condition failures passed as green")
	}
	if !strings.Contains(printed, torn) {
		t.Fatalf("teardown missing on the failing path; output:\n%s", printed)
	}
	noDown(t, calls)

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
	evidenceDir := filepath.Join(copyDir, ".evidence")
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
	code, _, printed = runHarness(t, exporting("exit 1"), false)
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

	// ── 5. SPEC K2: a held harness claim (another harness run: devseed-live,
	// e2e-full or another openid-conformance) refuses before any docker call
	// and is left as it was.
	if err := os.Mkdir(lock, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "pid"), []byte("held\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, calls, printed = runHarness(t, perPlan("exit 0"), false)
	if code == 0 || calls != "" || !strings.Contains(printed, "could not take the harness claim") {
		t.Fatalf("a held claim was not refused before any docker call (exit %d); docker calls:\n%s\noutput:\n%s", code, calls, printed)
	}
	if held, _ := os.ReadFile(filepath.Join(lock, "pid")); string(held) != "held\n" {
		t.Fatal("the held claim was changed")
	}
	if err := os.RemoveAll(lock); err != nil {
		t.Fatal(err)
	}

	// ── 6. SPEC K2: an engine that is not this host's unix socket is refused
	// before any docker call, and the claim is released (nothing was taken).
	code, calls, printed = runHarnessEnv(t, perPlan("exit 0"), false, "DOCKER_HOST=tcp://192.0.2.10:2376")
	if code == 0 || calls != "" || !strings.Contains(printed, "this host's own Docker engine") {
		t.Fatalf("a tcp DOCKER_HOST was not refused before any docker call (exit %d); docker calls:\n%s\noutput:\n%s", code, calls, printed)
	}
	released(t, printed)
}
