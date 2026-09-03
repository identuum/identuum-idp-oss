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
	rebase := flag.Bool("rebase", false, "write base_commit from the measured previous accepted witness and exit; judges nothing")
	flag.Parse()

	// THE-MANIFEST-CADENCE: the two modes are exclusive by construction. The
	// gate cannot write and the writer cannot judge, so a re-base can never
	// happen inside the run that is about to check the result.
	if *rebase {
		if err := rebaseManifest(*manifestPath, *repo); err != nil {
			fmt.Fprintln(os.Stderr, "ledger-rebase: FAIL —", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*manifestPath, *repo, *rulefloorBin, *printDoc); err != nil {
		fmt.Fprintln(os.Stderr, "ledger-diff-gate: FAIL —", err)
		os.Exit(1)
	}
}

// rebaseManifest derives base_commit from the SAME measurement the gate
// checks against — previousAcceptedWitness — and writes nothing else.
func rebaseManifest(manifestPath, repo string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("manifest %s: %w", manifestPath, err)
	}
	before, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	// RevRebase, not RevGate: the commit that will carry this manifest does
	// not exist yet, so the newest witness before it is the newest witness
	// reachable from HEAD right now.
	base, err := newestWitness(repo, RevRebase)
	if err != nil {
		return err
	}
	out, err := RebaseManifest(raw, base)
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", manifestPath, err)
	}
	fmt.Println(RebaseSummary(before.BaseCommit, base, len(before.Changes)))
	return nil
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

// RevGate and RevRebase are the two revisions the SAME rule is evaluated at.
//
// The rule is: the base is the newest witness that is an ancestor of the
// commit carrying the manifest, not counting that commit itself.
//
// The gate runs when the manifest is already committed, so that commit is
// HEAD and the search starts at HEAD~1. The re-base runs BEFORE that commit
// exists, so the commit-to-be is not in history yet and the search starts at
// HEAD. Same rule, two vantage points — and that is exactly why the derived
// value is still correct when the gate re-measures it after the commit
// lands. TestRuleLedgerRebaseDerivesBase1 pins the agreement across that
// boundary with a real git history.
const (
	RevGate   = "HEAD~1"
	RevRebase = "HEAD"
)

// previousAcceptedWitness: the newest witness commit strictly before HEAD.
func previousAcceptedWitness(repo string) (string, error) {
	return newestWitness(repo, RevGate)
}

// newestWitness is the single measurement both modes use.
func newestWitness(repo, rev string) (string, error) {
	cmd := exec.Command("git", "-C", repo, "log", "--format=%H", "-1", "--fixed-strings", "--grep="+WitnessSubjectPrefix, rev)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git log for the previous accepted witness: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sha := strings.TrimSpace(stdout.String())
	if sha == "" {
		return "", errors.New("previous accepted witness: no `" + WitnessSubjectPrefix + "` commit reachable from " + rev)
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
