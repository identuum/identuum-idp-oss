package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// grype-gate runs the scanner and judges its output (see decide.go for the
// ruling). It prints ONE evidence line for the gate-witness record and exits
// 0 pass / 1 fail / 2 cannot-evaluate.
//
//	grype-gate                      scan . and judge
//	grype-gate -scan report.json    judge a scan already taken
//
// Exit 2 is reserved for "the scanner could not run" — a gate that cannot
// evaluate must not be mistaken for one that passed, the same rule the
// integration gate follows.
//
// THE-JUDGE-AND-ITS-SUBJECT (2026-09-12): the judge names the SUBJECT it
// judges (subject.go) and evaluates only the predicates that subject admits.
// The applied-configuration predicate (a) and the exclude-coverage predicate
// (b) are statements about a directory; for an image subject they are NOT
// APPLICABLE and say so on the evidence line, and for a directory subject
// they read the subject's own tree, never the caller's.
const defaultAllowlist = "grype-allowlist.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: every path prints exactly one line to
// out and returns the exit code, so the driver is testable from fixtures.
func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("grype-gate", flag.ContinueOnError)
	fs.SetOutput(errOut)
	scan := fs.String("scan", "", "judge an existing grype JSON report instead of running the scanner")
	allowPath := fs.String("allowlist", defaultAllowlist, "path to the committed allowlist")
	root := fs.String("root", ".", "scan root: the repository whose .grype.yaml and gitignored executables are judged (a DIRECTORY subject's own tree; refused when it is not the scan's subject)")
	coverageOnly := fs.Bool("coverage-only", false, "run only the coverage predicate (b) — no scanner; used to red-prove a tree")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate: %v\n", err)
		return 2
	}
	rootExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "root" {
			rootExplicit = true
		}
	})

	// A scan already taken names its subject; a scan this gate takes is of
	// the directory it runs in.
	var raw []byte
	var subject Subject
	if *scan != "" {
		var err error
		raw, err = os.ReadFile(*scan)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot read the scan %s (%v)\n", *scan, err)
			return 2
		}
		subject, err = ParseSubject(raw)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
			return 2
		}
		switch {
		case subject.IsDirectory(), subject.IsImage():
		default:
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate: subject %s is neither a directory nor an image; the judge does not know which predicates it admits\n", subject.Label())
			return 2
		}
		if *coverageOnly && !subject.IsDirectory() {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate: -coverage-only judges a directory's tree; subject %s has none\n", subject.Label())
			return 2
		}
	}

	// The directory predicates: (b) coverage first and without the scanner —
	// a gitignored executable outside the exclude list would be judged as the
	// tree, so the scan is not worth paying for until the list covers the
	// repository — then, once the report exists, (a) applied configuration.
	// An IMAGE subject admits neither: it has no declaration and no
	// gitignored tree, and the line says so instead of passing quietly.
	configLine := "config: not applicable (image subject: no directory declaration to compare)"
	coverageLine := "coverage: not applicable (image subject: no gitignored tree to enumerate)"
	var decl Declaration
	subjectDir := ""
	if *scan == "" || subject.IsDirectory() {
		var err error
		if *scan == "" {
			subjectDir, err = filepath.Abs(*root)
			if err != nil {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot resolve root %s (%v)\n", *root, err)
				return 2
			}
			subject = Subject{Kind: "directory", Target: subjectDir}
		} else {
			subjectDir, err = subject.ResolveDir(*root, rootExplicit)
			if err != nil {
				fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
				return 2
			}
			subject.Target = subjectDir
		}
		declRaw, err := os.ReadFile(filepath.Join(subjectDir, ".grype.yaml"))
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot read %s/.grype.yaml (%v) — the exclude list is the subject's only fence\n", subjectDir, err)
			return 2
		}
		decl, err = ReadDeclaration(declRaw)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
			return 2
		}
		ignored, err := ListIgnoredExecutables(subjectDir)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate coverage: %v\n", err)
			return 2
		}
		var covered bool
		_, coverageLine, covered = CoverageDecide(ignored, decl.Exclude)
		if !covered {
			fmt.Fprintln(out, coverageLine)
			return 1
		}
		if *coverageOnly {
			fmt.Fprintln(out, "check OK: grype-gate "+coverageLine)
			return 0
		}
	}

	if *scan == "" {
		cmd := exec.Command("grype", "dir:.", "--output", "json")
		cmd.Dir = subjectDir
		cmd.Stderr = errOut
		var err error
		raw, err = cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype exited %d without a report; a scanner that cannot run is never a pass\n", ee.ExitCode())
			} else {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype could not run (%v); a scanner that cannot run is never a pass\n", err)
			}
			return 2
		}
		got, err := ParseSubject(raw)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
			return 2
		}
		if !got.IsDirectory() {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate scanned dir:. yet the report names subject %s\n", got.Label())
			return 2
		}
	}

	doc, err := ParseDoc(raw)
	if err != nil {
		fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
		return 2
	}

	var allow Allowlist
	allowRaw, readErr := os.ReadFile(*allowPath)
	switch {
	case readErr == nil:
		allow, err = ParseAllowlist(allowRaw)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
			return 2
		}
	case errors.Is(readErr, os.ErrNotExist):
		// No allowlist is the ordinary state: nothing is excused.
	default:
		fmt.Fprintf(out, "CANNOT-EVALUATE: allowlist %s unreadable (%v)\n", *allowPath, readErr)
		return 2
	}

	if subject.IsDirectory() {
		// (a) APPLIED: the scanner is asked what configuration it used, and
		// that must be the subject's committed declaration — a report that
		// does not say is not a pass, and a report that says something else
		// is a failure.
		cfg, present, err := ParseScanConfig(raw)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
			return 2
		}
		if !present {
			fmt.Fprintln(out, "CANNOT-EVALUATE: grype-gate config: the report carries no descriptor.configuration, so whether .grype.yaml was applied cannot be judged")
			return 2
		}
		var applied bool
		configLine, applied = CompareConfig(cfg, decl, subjectDir)
		if !applied {
			fmt.Fprintln(out, configLine)
			return 1
		}
	}

	_, summary, ok := Decide(doc, allow)
	// ONE evidence line for the gate-witness record: the verdict, the subject
	// it was reached on, then the two predicates — applied or not applicable.
	fmt.Fprintln(out, summary+" — subject "+subject.Label()+"; "+configLine+"; "+coverageLine)
	if !ok {
		return 1
	}
	return 0
}
