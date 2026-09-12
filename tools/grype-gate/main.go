package main

import (
	"errors"
	"flag"
	"fmt"
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
const defaultAllowlist = "grype-allowlist.json"

func main() {
	scan := flag.String("scan", "", "judge an existing grype JSON report instead of running the scanner")
	allowPath := flag.String("allowlist", defaultAllowlist, "path to the committed allowlist")
	root := flag.String("root", ".", "scan root: the repository whose .grype.yaml and gitignored executables are judged")
	coverageOnly := flag.Bool("coverage-only", false, "run only the coverage predicate (b) — no scanner; used to red-prove a tree")
	flag.Parse()

	// THE-GRYPE-SUBJECT: the two predicates that keep `dir:.` an honest
	// subject. (b) runs first and without the scanner: a gitignored executable
	// outside the exclude list would be judged as the tree, so the scan is not
	// worth paying for until the list covers the repository.
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: grype-gate cannot resolve root %s (%v)\n", *root, err)
		os.Exit(2)
	}
	declRaw, err := os.ReadFile(filepath.Join(absRoot, ".grype.yaml"))
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: grype-gate cannot read %s/.grype.yaml (%v) — the exclude list is the subject's only fence\n", absRoot, err)
		os.Exit(2)
	}
	decl, err := ReadDeclaration(declRaw)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: %v\n", err)
		os.Exit(2)
	}
	ignored, err := ListIgnoredExecutables(absRoot)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: grype-gate coverage: %v\n", err)
		os.Exit(2)
	}
	_, coverageLine, covered := CoverageDecide(ignored, decl.Exclude)
	if !covered {
		fmt.Println(coverageLine)
		os.Exit(1)
	}
	if *coverageOnly {
		fmt.Println("check OK: grype-gate " + coverageLine)
		return
	}

	var raw []byte
	if *scan != "" {
		raw, err = os.ReadFile(*scan)
		if err != nil {
			fmt.Printf("CANNOT-EVALUATE: grype-gate cannot read the scan %s (%v)\n", *scan, err)
			os.Exit(2)
		}
	} else {
		cmd := exec.Command("grype", "dir:.", "--output", "json")
		cmd.Dir = absRoot
		cmd.Stderr = os.Stderr
		raw, err = cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				fmt.Printf("CANNOT-EVALUATE: grype exited %d without a report; a scanner that cannot run is never a pass\n", ee.ExitCode())
			} else {
				fmt.Printf("CANNOT-EVALUATE: grype could not run (%v); a scanner that cannot run is never a pass\n", err)
			}
			os.Exit(2)
		}
	}

	doc, err := ParseDoc(raw)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: %v\n", err)
		os.Exit(2)
	}

	var allow Allowlist
	allowRaw, readErr := os.ReadFile(*allowPath)
	switch {
	case readErr == nil:
		allow, err = ParseAllowlist(allowRaw)
		if err != nil {
			fmt.Printf("CANNOT-EVALUATE: %v\n", err)
			os.Exit(2)
		}
	case errors.Is(readErr, os.ErrNotExist):
		// No allowlist is the ordinary state: nothing is excused.
	default:
		fmt.Printf("CANNOT-EVALUATE: allowlist %s unreadable (%v)\n", *allowPath, readErr)
		os.Exit(2)
	}

	// (a) APPLIED: the scanner is asked what configuration it used, and that
	// must be the committed declaration — a report that does not say is not a
	// pass, and a report that says something else is a failure.
	cfg, present, err := ParseScanConfig(raw)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: %v\n", err)
		os.Exit(2)
	}
	if !present {
		fmt.Println("CANNOT-EVALUATE: grype-gate config: the report carries no descriptor.configuration, so whether .grype.yaml was applied cannot be judged")
		os.Exit(2)
	}
	configLine, applied := CompareConfig(cfg, decl, absRoot)
	if !applied {
		fmt.Println(configLine)
		os.Exit(1)
	}

	_, summary, ok := Decide(doc, allow)
	// ONE evidence line for the gate-witness record: the verdict, then the
	// two predicates that make the subject honest.
	fmt.Println(summary + " — " + configLine + "; " + coverageLine)
	if !ok {
		os.Exit(1)
	}
}
