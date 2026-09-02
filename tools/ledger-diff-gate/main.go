package main

// main.go — I/O for the ledger-diff gate: reads the manifest, measures the
// previous accepted witness from git, runs rulefloor, and prints ONE line:
// the `check OK:` evidence line on pass, or the reconciliation problems and
// exit 1 on failure. Nothing here can "fix" anything; it only refuses.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// WitnessSubjectPrefix is the record-only commit the close ritual writes
// after a green verify; the most recent one before HEAD is the base.
const WitnessSubjectPrefix = "Witness: make verify green at "

func main() {
	manifestPath := flag.String("manifest", "ledger-amendments.json", "committed ledger-amendments.v1 manifest")
	repo := flag.String("repo", ".", "repository root")
	rulefloorBin := flag.String("rulefloor", "rulefloor", "rulefloor binary")
	printDoc := flag.Bool("print-doc", false, "also print the rulefloor ledger-diff.v1 document to stderr")
	flag.Parse()

	if err := run(*manifestPath, *repo, *rulefloorBin, *printDoc); err != nil {
		fmt.Fprintln(os.Stderr, "ledger-diff-gate: FAIL —", err)
		os.Exit(1)
	}
}

func run(manifestPath, repo, rulefloorBin string, printDoc bool) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("manifest %s: %w (every verify needs a committed, SHA-scoped manifest — an empty changes list is fine)", manifestPath, err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	base, err := previousAcceptedWitness(repo)
	if err != nil {
		return err
	}
	doc, exitCode, err := runLedgerDiff(rulefloorBin, repo, base)
	if err != nil {
		return err
	}
	if printDoc {
		fmt.Fprintln(os.Stderr, string(doc))
	}
	sum := sha256.Sum256(doc)
	out, err := Reconcile(m, doc, exitCode, base, hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	fmt.Println(out.EvidenceLine())
	return nil
}

// previousAcceptedWitness: the newest witness commit strictly before HEAD.
func previousAcceptedWitness(repo string) (string, error) {
	cmd := exec.Command("git", "-C", repo, "log", "--format=%H", "-1", "--fixed-strings", "--grep="+WitnessSubjectPrefix, "HEAD~1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git log for the previous accepted witness: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sha := strings.TrimSpace(stdout.String())
	if sha == "" {
		return "", errors.New("previous accepted witness: no `" + WitnessSubjectPrefix + "` commit reachable from HEAD~1")
	}
	return sha, nil
}

// runLedgerDiff returns the raw document and rulefloor's exit code
// (0 same, 1 different, 2 cannot evaluate).
func runLedgerDiff(bin, repo, base string) ([]byte, int, error) {
	cmd := exec.Command(bin, "ledger-diff", "--base", base, "--json", "--repo", repo)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return nil, -1, fmt.Errorf("run %s ledger-diff: %w", bin, err)
		}
	}
	doc := stdout.Bytes()
	if len(bytes.TrimSpace(doc)) == 0 {
		doc = stderr.Bytes()
	}
	return doc, code, nil
}
