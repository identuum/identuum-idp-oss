package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// grype-gate runs the scanner and judges its output (see decide.go for the
// ruling). It prints ONE evidence line for the gate-witness record and exits
// 0 pass / 1 fail / 2 cannot-evaluate.
//
//	grype-gate                                      scan . and judge
//	grype-gate -scan report.json -inventory bom.json judge a scan already taken,
//	                                                with the CycloneDX inventory
//	                                                grype wrote beside it
//	grype-gate -coverage-only -inventory bom.json   judge only what the scanner
//	                                                saw against the tree
//
// Exit 2 is reserved for "the scanner could not run" — a gate that cannot
// evaluate must not be mistaken for one that passed, the same rule the
// integration gate follows.
//
// THE-JUDGE-AND-ITS-SUBJECT (2026-09-12): the judge names the SUBJECT it
// judges (subject.go) and evaluates only the predicates that subject admits.
// The applied-configuration predicate (a) and the coverage predicate (b) are
// statements about a directory; for an image subject they are NOT APPLICABLE
// and say so on the evidence line, and for a directory subject they read the
// subject's own tree, never the caller's.
//
// THE-SCANNER-THAT-SAYS-WHAT-IT-SAW (2026-09-16): predicate (b) is over what
// grype SAW. One scan writes two reports — the JSON report the verdict reads
// and the CycloneDX inventory of every component it catalogued, with the path
// of each — and no component may sit at a path git reports as ignored. A
// directory scan judged without its inventory is CANNOT-EVALUATE.
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
	inventory := fs.String("inventory", "", "the CycloneDX-JSON inventory (`grype … -o cyclonedx-json`) taken with the -scan report: what the scanner SAW; a directory subject's coverage predicate is judged on it and is CANNOT-EVALUATE without it")
	allowPath := fs.String("allowlist", defaultAllowlist, "path to the committed allowlist")
	root := fs.String("root", ".", "scan root: the repository whose .grype.yaml and gitignored paths are judged (a DIRECTORY subject's own tree; refused when it is not the scan's subject)")
	coverageOnly := fs.Bool("coverage-only", false, "run only the coverage predicate (b) over -inventory against -root's gitignored paths — no scanner; used to red-prove a tree")
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

	// -coverage-only: the inventory against the tree, nothing else. It needs
	// no scanner and no declaration — only what grype saw and what git ignores.
	if *coverageOnly {
		if *scan != "" {
			raw, err := os.ReadFile(*scan)
			if err != nil {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot read the scan %s (%v)\n", *scan, err)
				return 2
			}
			subject, err := ParseSubject(raw)
			if err != nil {
				fmt.Fprintf(out, "CANNOT-EVALUATE: %v\n", err)
				return 2
			}
			if !subject.IsDirectory() {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate: -coverage-only judges a directory's tree; subject %s has none\n", subject.Label())
				return 2
			}
		}
		if *inventory == "" {
			fmt.Fprintln(out, "CANNOT-EVALUATE: grype-gate: -coverage-only judges what the scanner saw, and no -inventory was given")
			return 2
		}
		subjectDir, err := filepath.Abs(*root)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot resolve root %s (%v)\n", *root, err)
			return 2
		}
		line, ok, code := judgeInventory(*inventory, nil, subjectDir)
		if code != 0 {
			fmt.Fprintln(out, line)
			return code
		}
		if !ok {
			fmt.Fprintln(out, line)
			return 1
		}
		fmt.Fprintln(out, "check OK: grype-gate "+line)
		return 0
	}

	// A scan already taken names its subject; a scan this gate takes is of
	// the directory it runs in.
	var raw, invRaw []byte
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
	}

	// The directory predicates read the subject's own tree: its declaration
	// for (a), its gitignored paths for (b). An IMAGE subject admits neither:
	// it has no declaration and no gitignored tree, and the line says so
	// instead of passing quietly.
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
	}

	if *scan == "" {
		// One scan, two reports: the JSON report for the verdict and the
		// CycloneDX inventory for what the scanner saw. Both go to files
		// grype writes itself, so neither can be mistaken for the other.
		tmp, err := os.MkdirTemp("", "grype-gate")
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype-gate cannot make a scratch directory (%v)\n", err)
			return 2
		}
		defer os.RemoveAll(tmp)
		reportPath := filepath.Join(tmp, "report.json")
		inventoryPath := filepath.Join(tmp, "inventory.cdx.json")
		cmd := exec.Command("grype", "dir:.", "--output", "json="+reportPath, "--output", "cyclonedx-json="+inventoryPath)
		cmd.Dir = subjectDir
		cmd.Stderr = errOut
		if _, err := cmd.Output(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype exited %d without a report; a scanner that cannot run is never a pass\n", ee.ExitCode())
			} else {
				fmt.Fprintf(out, "CANNOT-EVALUATE: grype could not run (%v); a scanner that cannot run is never a pass\n", err)
			}
			return 2
		}
		raw, err = os.ReadFile(reportPath)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype wrote no JSON report (%v); a scanner that cannot run is never a pass\n", err)
			return 2
		}
		invRaw, err = os.ReadFile(inventoryPath)
		if err != nil {
			fmt.Fprintf(out, "CANNOT-EVALUATE: grype wrote no CycloneDX inventory (%v); what it saw cannot be judged\n", err)
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
		// THE-EIGHT-QUICK-ONES, OSS 2 (2026-09-16): the declaration's own
		// re-check dates are a predicate too. A suppression past its date is
		// a RED finding about .grype.yaml, naming the entry and the date.
		recheckLine, current := LapsedSuppressions(decl, time.Now().UTC())
		if !current {
			fmt.Fprintln(out, recheckLine)
			return 1
		}
		configLine += "; " + recheckLine

		// (b) COVERAGE, over what the scanner SAW: the inventory taken with
		// this report (the scan's own, or the one named beside -scan). A
		// directory judged without one is undecidable, never a pass.
		if *scan != "" && *inventory == "" {
			fmt.Fprintln(out, "CANNOT-EVALUATE: grype-gate coverage: a directory scan is judged on the CycloneDX inventory grype wrote beside it, and none was given (-inventory) — what the scanner saw cannot be judged")
			return 2
		}
		var covered bool
		var code int
		coverageLine, covered, code = judgeInventory(*inventory, invRaw, subjectDir)
		if code != 0 {
			fmt.Fprintln(out, coverageLine)
			return code
		}
		if !covered {
			fmt.Fprintln(out, coverageLine)
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

// judgeInventory reads the inventory (from the path when given, else the
// bytes the scan wrote) and judges it against the subject's gitignored paths.
// It returns the line, whether coverage held, and a non-zero code when the
// inventory or the tree could not be read (CANNOT-EVALUATE, 2).
func judgeInventory(path string, raw []byte, subjectDir string) (line string, ok bool, code int) {
	if path != "" {
		var err error
		raw, err = os.ReadFile(path)
		if err != nil {
			return fmt.Sprintf("CANNOT-EVALUATE: grype-gate cannot read the inventory %s (%v)", path, err), false, 2
		}
	}
	inv, err := ParseInventory(raw, subjectDir)
	if err != nil {
		return "CANNOT-EVALUATE: " + err.Error(), false, 2
	}
	ignored, err := ListIgnoredPaths(subjectDir)
	if err != nil {
		return "CANNOT-EVALUATE: grype-gate coverage: " + err.Error(), false, 2
	}
	_, line, ok = InventoryDecide(inv, ignored)
	return line, ok, 0
}
