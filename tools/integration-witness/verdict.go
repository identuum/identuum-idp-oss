// Package main — integration-witness (THE-UNRUN-SUITE, 2026-09-03).
//
// WHY THIS EXISTS
// ---------------
// `make verify` type-checks the integration-tagged files (vet-integration) but
// RUNS nothing in them. Two defects reached a witness through that gap: a
// bundle fixture broken by the owner-binding slice (latent one slice) and the
// advertised RS256 list (latent two days, with a test on the right side of the
// ruling sitting red the whole time).
//
// The owner's ruling (P-041) is a SEPARATE `make verify-integration`, wired
// into the two-repo mint, leaving `make verify` database-free. This tool is
// that gate's judgement: it runs the profile and turns its output into ONE
// evidence line the gate-witness record carries, with three outcomes and no
// fourth.
//
//	green            every executed test passed AND tests actually ran
//	red              a test failed, or the runner itself failed
//	cannot-evaluate  no database — exit 2, NEVER a pass
//
// The vacuous case is the point of the slice: a run that executes NO tests is
// not green. "The suite did not run" is exactly the failure this gate exists
// to make loud, so it can never read as success.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Verdict is the gate's answer. The zero value is deliberately the failing
// one: a classifier that returns early must not read as green.
type Verdict int

const (
	// VerdictRed — a test failed or the runner did.
	VerdictRed Verdict = iota
	// VerdictGreen — tests ran and all of them passed.
	VerdictGreen
	// VerdictCannotEvaluate — the profile could not run at all (no database).
	VerdictCannotEvaluate
)

// ExitCode is what the process returns for a verdict: 0 green, 1 red,
// 2 cannot-evaluate. Two is distinct on purpose — a gate that cannot run is
// not a gate that passed.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictGreen:
		return 0
	case VerdictCannotEvaluate:
		return 2
	default:
		return 1
	}
}

// Counts are the numbers the evidence line carries.
type Counts struct {
	Packages int // packages that reported ok/FAIL (not "no test files")
	Passed   int // --- PASS lines (top-level and subtests)
	Failed   int // --- FAIL lines
	Skipped  int // --- SKIP lines
}

// noDatabaseSignatures are the shapes the profile produces when there is no
// database to talk to. Each is a MEASURED string from this repository's own
// harness or from pgx, not a guess.
var noDatabaseSignatures = []string{
	"IDENTUUM_IDP_TEST_DATABASE_URL", // the harness's own fatal when the DSN is unset
	"connection refused",             // nothing listening on the port
	"no such host",                   // the host does not resolve
	"database system is starting up", // container up, server not ready
	"SQLSTATE 3D000",                 // database does not exist
	"failed to connect to `user=",    // pgx dial failure preamble
	"server closed the connection unexpectedly",
}

var (
	rePass    = regexp.MustCompile(`(?m)^\s*--- PASS: `)
	reFail    = regexp.MustCompile(`(?m)^\s*--- FAIL: `)
	reSkip    = regexp.MustCompile(`(?m)^\s*--- SKIP: `)
	rePkgOK   = regexp.MustCompile(`(?m)^ok\s+\S+`)
	rePkgFail = regexp.MustCompile(`(?m)^FAIL\s+\S+`)
	reBuild   = regexp.MustCompile(`(?m)^(# |.*\[build failed\]|.*cannot find package)`)
)

// Classify turns the runner's combined output and its process error into the
// gate's verdict, the counts, and the ONE line the record carries.
//
// runFailed is whether the `go test` process itself exited nonzero; it is
// deliberately not the only input, because a run that exits 0 having executed
// nothing must still be refused.
func Classify(output string, runFailed bool) (Verdict, Counts, string) {
	c := Counts{
		Passed:   len(rePass.FindAllString(output, -1)),
		Failed:   len(reFail.FindAllString(output, -1)),
		Skipped:  len(reSkip.FindAllString(output, -1)),
		Packages: len(rePkgOK.FindAllString(output, -1)) + len(rePkgFail.FindAllString(output, -1)),
	}

	// (1) No database is not a verdict about the code. It outranks a failure
	// count, because every DB-backed test fails the same way without one and
	// reporting that as "red" would blame the tree for the environment.
	if c.Passed == 0 || c.Failed > 0 {
		for _, sig := range noDatabaseSignatures {
			if strings.Contains(output, sig) {
				return VerdictCannotEvaluate, c, fmt.Sprintf(
					"CANNOT-EVALUATE: integration-profile has no database (matched %q); a missing database is never a pass", sig)
			}
		}
	}

	// (2) A build failure is red, not "nothing ran".
	if c.Passed == 0 && reBuild.MatchString(output) {
		return VerdictRed, c, "check FAILED: integration-profile did not build"
	}

	// (3) THE VACUOUS RUN. Zero executed tests is the failure this gate
	// exists for: a profile that silently stops running must never be green.
	if c.Passed == 0 && c.Failed == 0 {
		return VerdictRed, c, fmt.Sprintf(
			"check FAILED: integration-profile ran NO tests (packages=%d) — a suite that does not run is not a suite that passed", c.Packages)
	}

	if c.Failed > 0 || runFailed {
		return VerdictRed, c, fmt.Sprintf(
			"check FAILED: integration-profile packages=%d passed=%d skipped=%d failed=%d",
			c.Packages, c.Passed, c.Skipped, c.Failed)
	}

	return VerdictGreen, c, fmt.Sprintf(
		"check OK: integration-profile packages=%d passed=%d skipped=%d failed=0",
		c.Packages, c.Passed, c.Skipped)
}
