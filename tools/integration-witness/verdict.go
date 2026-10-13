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
	"net"
	"regexp"
	"slices"
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

// THE-HIDDEN-RED (OSS-INTEGRATION-WITNESS-FIX). A missing database is judged
// ONLY from the failed tests' own lines, and only by shapes no other backend
// prints. The bare "connection refused" once matched anywhere in the run: the
// redis and SMTP suites log it by design while they PASS, so a real failure
// beside them read as "no database" and its package was lost.
const pgxConnectPreamble = "failed to connect to `user=" // pgx ConnectError; the address follows

var (
	// reMissingDSN is the harness's own fatal when the DSN is unset, in both
	// MEASURED wordings (internal/e2e, internal/postgres, internal/runtime).
	reMissingDSN = regexp.MustCompile(`IDENTUUM_IDP_TEST_DATABASE_URL (\(or IDENTUUM_IDP_DATABASE_URL\) )?is not set`)
	// reDiag is a test's own diagnostic (t.Log, t.Error, t.Fatal): file.go:N:.
	reDiag = regexp.MustCompile(`(?m)^\s+\S+\.go:\d+: `)

	reTestHead = regexp.MustCompile(`^=== (?:RUN|CONT|NAME|PAUSE)\s+(\S+)`)
	reTestEnd  = regexp.MustCompile(`^\s*--- (PASS|FAIL|SKIP): (\S+)`)
	rePkgEnd   = regexp.MustCompile(`^(ok|FAIL|\?)[ \t]+(\S+)`)
)

var (
	rePass    = regexp.MustCompile(`(?m)^\s*--- PASS: `)
	reFail    = regexp.MustCompile(`(?m)^\s*--- FAIL: `)
	reSkip    = regexp.MustCompile(`(?m)^\s*--- SKIP: `)
	rePkgOK   = regexp.MustCompile(`(?m)^ok\s+\S+`)
	rePkgFail = regexp.MustCompile(`(?m)^FAIL\s+\S+`)
	reBuild   = regexp.MustCompile(`(?m)^(# |.*\[build failed\]|.*cannot find package)`)
)

// dbSignature names the database-only shape text carries, or "". port is the
// DSN's port: a pgx connect error counts only when it names that port, so a
// test dialling some other server cannot pass for the database.
func dbSignature(text, port string) string {
	switch {
	case port != "" && strings.Contains(text, pgxConnectPreamble) && strings.Contains(text, ":"+port+" ("):
		return "pgx connect to :" + port
	case strings.Contains(text, "(SQLSTATE 3D000)"):
		return "SQLSTATE 3D000"
	case reMissingDSN.MatchString(text):
		return "IDENTUUM_IDP_TEST_DATABASE_URL is not set"
	}
	return ""
}

// failure is one failed test, or a package that failed with no failed test
// (TestMain, init, a build or setup failure); test is "" for the latter.
type failure struct {
	pkg, test string
	text      string // the lines go test attributed to it
	parent    bool   // a failed subtest of it exists
}

func (f failure) name() string {
	if f.test == "" {
		return f.pkg
	}
	return f.pkg + "." + f.test
}

// failures reads `go test -v -p 1` output: packages run one after another and
// end in an ok/FAIL/? line, and a test's lines are those after its
// === RUN/CONT/NAME header (streamed) or after its --- line (buffered), up to
// the next header or result line.
func failures(output string) []failure {
	var out []failure
	var failed []string
	blocks := map[string]*strings.Builder{}
	var pkgText strings.Builder
	cur := ""
	flush := func(pkg string) {
		if len(failed) == 0 {
			out = append(out, failure{pkg: pkg, text: pkgText.String()})
		}
		for _, name := range failed {
			f := failure{pkg: pkg, test: name}
			if b := blocks[name]; b != nil {
				f.text = b.String()
			}
			for _, other := range failed {
				f.parent = f.parent || strings.HasPrefix(other, name+"/")
			}
			out = append(out, f)
		}
	}
	reset := func() {
		failed, blocks, cur = nil, map[string]*strings.Builder{}, ""
		pkgText.Reset()
	}
	for _, line := range strings.Split(output, "\n") {
		if m := rePkgEnd.FindStringSubmatch(line); m != nil {
			if m[1] == "FAIL" {
				flush(m[2])
			}
			reset()
			continue
		}
		pkgText.WriteString(line + "\n")
		if m := reTestHead.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if m := reTestEnd.FindStringSubmatch(line); m != nil {
			cur = m[2]
			if m[1] == "FAIL" {
				failed = append(failed, cur)
			}
			continue
		}
		if blocks[cur] == nil {
			blocks[cur] = &strings.Builder{}
		}
		blocks[cur].WriteString(line + "\n")
	}
	if len(failed) > 0 { // a run cut off before its package line
		flush("(unknown package)")
	}
	return out
}

// explained is the database signature that accounts for f, or "". A parent
// failed by its subtests is accounted for by them (they are judged on their
// own), unless it printed a diagnostic of its own.
func explained(f failure, port string) string {
	if sig := dbSignature(f.text, port); sig != "" {
		return sig
	}
	if f.parent && !reDiag.MatchString(f.text) {
		return "failed subtests"
	}
	return ""
}

// Classify turns the runner's combined output and its process error into the
// gate's verdict, the counts, and the ONE line the record carries.
//
// runFailed is whether the `go test` process itself exited nonzero; it is
// deliberately not the only input, because a run that exits 0 having executed
// nothing must still be refused. dbAddr is the DSN's host:port.
func Classify(output string, runFailed bool, dbAddr string) (Verdict, Counts, string) {
	c := Counts{
		Passed:   len(rePass.FindAllString(output, -1)),
		Failed:   len(reFail.FindAllString(output, -1)),
		Skipped:  len(reSkip.FindAllString(output, -1)),
		Packages: len(rePkgOK.FindAllString(output, -1)) + len(rePkgFail.FindAllString(output, -1)),
	}
	_, port, _ := net.SplitHostPort(dbAddr)

	// (1) No database is not a verdict about the code: when EVERY failure
	// shows a database-only shape, the run says nothing about the tree. One
	// failure without one is red, and the first such failure is named.
	fs := failures(output)
	var unexplained []failure
	sig := ""
	for _, f := range fs {
		s := explained(f, port)
		if s == "" {
			unexplained = append(unexplained, f)
		} else if sig == "" || sig == "failed subtests" {
			sig = s
		}
	}
	if len(fs) > 0 && len(unexplained) == 0 {
		return VerdictCannotEvaluate, c, fmt.Sprintf(
			"CANNOT-EVALUATE: integration-profile has no database (every failure, %d, shows it; first=%s matched %q); a missing database is never a pass",
			len(fs), fs[0].name(), sig)
	}
	// A run where nothing passed and nothing failed is judged on its whole
	// output, by the same database-only shapes.
	if len(fs) == 0 && c.Passed == 0 {
		if s := dbSignature(output, port); s != "" {
			return VerdictCannotEvaluate, c, fmt.Sprintf(
				"CANNOT-EVALUATE: integration-profile has no database (matched %q); a missing database is never a pass", s)
		}
	}

	// (2) A build failure is red, not "nothing ran".
	if c.Passed == 0 && reBuild.MatchString(output) {
		return VerdictRed, c, "check FAILED: integration-profile did not build"
	}

	// (3) THE VACUOUS RUN. Zero executed tests is the failure this gate
	// exists for: a profile that silently stops running must never be green.
	if c.Passed == 0 && len(fs) == 0 {
		return VerdictRed, c, fmt.Sprintf(
			"check FAILED: integration-profile ran NO tests (packages=%d) — a suite that does not run is not a suite that passed", c.Packages)
	}

	if len(fs) > 0 || runFailed {
		line := fmt.Sprintf("check FAILED: integration-profile packages=%d passed=%d skipped=%d failed=%d",
			c.Packages, c.Passed, c.Skipped, c.Failed)
		if len(unexplained) > 0 {
			var pkgs []string
			for _, f := range fs {
				if !slices.Contains(pkgs, f.pkg) {
					pkgs = append(pkgs, f.pkg)
				}
			}
			line += fmt.Sprintf(" first=%s failed_packages=%s", unexplained[0].name(), strings.Join(pkgs, ","))
		}
		return VerdictRed, c, line
	}

	return VerdictGreen, c, fmt.Sprintf(
		"check OK: integration-profile packages=%d passed=%d skipped=%d failed=0",
		c.Packages, c.Passed, c.Skipped)
}
