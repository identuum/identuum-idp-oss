package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	flag.Parse()

	var raw []byte
	var err error
	if *scan != "" {
		raw, err = os.ReadFile(*scan)
		if err != nil {
			fmt.Printf("CANNOT-EVALUATE: grype-gate cannot read the scan %s (%v)\n", *scan, err)
			os.Exit(2)
		}
	} else {
		cmd := exec.Command("grype", "dir:.", "--output", "json")
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

	_, summary, ok := Decide(doc, allow)
	fmt.Println(summary)
	if !ok {
		os.Exit(1)
	}
}
