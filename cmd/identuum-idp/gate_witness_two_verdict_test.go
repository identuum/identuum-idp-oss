package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// THE-TWO-VERDICT-RECORD (2026-09-04): P-057's reviewer constructed a record
// that TWO runs had written into — a `run` starting between an `init` and its
// `finalize` truncates the stepwise session's header and leaves two `gate:`
// lines and two `result:` verdicts in one file — and watched `check` answer
// "gate-witness OK ... (2 targets)", exit 0.
//
// It passed because every reader inside check takes the FIRST of each line
// (`sed ... | head -1`), so run B's plan sat above run A's targets and run B's
// verdict decided what the reader believed. The record certifying every other
// gate could itself be two runs deep and say nothing about it.
//
// This pins the backstop: more than one `gate:` header or more than one
// `result:` verdict is REFUSED, and the refusal COUNTS what it found so a
// reader can tell a two-run collision from a malformed file.
//
// WHAT THIS DOES NOT DO, stated so the rule is not read as more than it is:
// it does not stop the interleaving. GATE-WITNESS-STEPWISE-1 is still open —
// init/step/finalize take the record lock per invocation. This stops an
// interleaved record from being BELIEVED, which is the half that can be fixed
// in the reader.
//
// The script under test is the VENDORED copy this repo's `make verify` runs;
// --sync-check holds it byte-identical to the wiki master.
//
// RULE: WITNESS-ONE-RUN-PER-RECORD-1
func TestGateWitness_TwoVerdictRecordIsRefused(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "gate-witness.sh"))
	if err != nil {
		t.Fatalf("resolve script: %v", err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("vendored gate-witness.sh not found: %v", err)
	}

	// One finalized run's record, in the shape write_header + finalize_into
	// produce. It is deliberately NOT a valid green record for this tree —
	// the interleaving check fires before any plan, target or digest work,
	// and pinning it here keeps the fixture readable.
	oneRun := strings.Join([]string{
		"schema: gate-run.v1",
		"gate: selftest one-run",
		"repo-head: deadbee",
		"plan: a",
		"target: a exit=0",
		"result: green",
		"",
	}, "\n")

	check := func(t *testing.T, body string) (string, int) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "GATE-RUN.txt"), []byte(body), 0o600); err != nil {
			t.Fatalf("write record: %v", err)
		}
		cmd := exec.Command("bash", script, "check", dir, "GATE-RUN.txt")
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("run check: %v", err)
		}
		return string(out), code
	}

	// TWO runs in one file: refused, by name, with the counts.
	out, code := check(t, oneRun+oneRun)
	if code == 0 {
		t.Fatalf("a record with TWO verdicts passed check (exit 0) — an interleaved record would be believed:\n%s", out)
	}
	if !strings.Contains(out, "GATE-WITNESS INTERLEAVED") {
		t.Fatalf("refusal does not name the interleaving:\n%s", out)
	}
	if !strings.Contains(out, "2 'gate:' header(s)") || !strings.Contains(out, "2 'result:' verdict(s)") {
		t.Fatalf("refusal does not COUNT what it found — a reader cannot tell two runs from a malformed file:\n%s", out)
	}

	// ONE run: this check must not fire. The record still fails for other
	// reasons (it names a tree this directory is not), which is the point of
	// asserting the ABSENCE of the interleaving verdict rather than success:
	// it isolates the new refusal from every older one.
	out, code = check(t, oneRun)
	if code == 0 {
		t.Fatalf("fixture error: the single-run record was expected to fail on its tree, got exit 0:\n%s", out)
	}
	if strings.Contains(out, "GATE-WITNESS INTERLEAVED") {
		t.Fatalf("a single-run record was refused as interleaved — the check counts wrongly:\n%s", out)
	}
}
