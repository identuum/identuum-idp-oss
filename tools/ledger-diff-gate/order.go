package main

// order.go — OSS-LEDGER-ORDER (2026-10-05).
//
// agent-rules.md:884: "A LEDGER REBASE IS THE FIRST COMMIT AFTER A WITNESS IS
// ACCEPTED, committed ALONE". The base_commit check cannot see where the
// rebase sits in history, so a late or crowded rebase passed it (OSS f209688,
// OSS 01cfb99, ui ce4b201). This judges the order.
//
// THE CYCLE is the commits after the newest witness reachable from HEAD, up
// to HEAD — RevRebase's vantage, so a HEAD that is itself a witness has an
// empty cycle: nothing owed, nothing judged (OSS-RECORD-REFRESH verified at
// a witness head with no rebase). Older cycles are never judged: their own
// verify judged them before their witness was minted.
//
// Every non-empty cycle owes a rebase: the witness opening it moved the base,
// and the manifest committed before it names the witness before that. So the
// first commit changes the manifest, no later commit does, and the commit
// that does changes nothing else. Uncommitted state is not looked at here; the
// base_commit check keeps judging it as before.

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// CycleCommit is one commit of the cycle, oldest first.
type CycleCommit struct {
	SHA   string
	Paths []string
}

// CheckRebaseOrder returns "" when the cycle opens with the manifest change
// alone, or the problems found, named by commit.
func CheckRebaseOrder(cycle []CycleCommit, manifest string) []string {
	if len(cycle) == 0 {
		return nil
	}
	var problems []string
	if !slices.Contains(cycle[0].Paths, manifest) {
		problems = append(problems, fmt.Sprintf("%s opens the cycle without changing %s", short(cycle[0].SHA), manifest))
	}
	for i, c := range cycle {
		if !slices.Contains(c.Paths, manifest) {
			continue
		}
		if i > 0 {
			problems = append(problems, fmt.Sprintf("%s changes %s as commit %d of the cycle, not the first", short(c.SHA), manifest, i+1))
		}
		if others := slices.DeleteFunc(slices.Clone(c.Paths), func(p string) bool { return p == manifest }); len(others) > 0 {
			problems = append(problems, fmt.Sprintf("%s changes %s together with %s", short(c.SHA), manifest, strings.Join(others, ", ")))
		}
	}
	return problems
}

// OrderFailure is the one line the gate prints for a cycle out of order.
func OrderFailure(witness string, problems []string) string {
	return fmt.Sprintf("ledger rebase out of order since witness %s: %s — the first commit after a witness must be the ledger rebase alone: reorder the unpushed commits (with the owner's leave) so `make ledger-rebase` and a commit of ledger-amendments.json alone come first",
		short(witness), strings.Join(problems, "; "))
}

// judgeCycle measures the cycle from git and returns the failure, if any.
func judgeCycle(repo, manifestPath string) error {
	witness, err := newestWitness(repo, RevRebase)
	if err != nil {
		return err
	}
	top, err := gitOut(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	// git prints the toplevel with symlinks resolved (/private/var on macOS)
	absManifest, err := filepath.Abs(manifestPath)
	if err == nil {
		absManifest, err = filepath.EvalSymlinks(absManifest)
	}
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(top); err == nil {
		top = resolved
	}
	rel, err := filepath.Rel(top, absManifest)
	if err != nil {
		return fmt.Errorf("manifest %s is not inside %s: %w", manifestPath, top, err)
	}
	shas, err := gitOut(repo, "rev-list", "--reverse", witness+"..HEAD")
	if err != nil {
		return err
	}
	var cycle []CycleCommit
	for _, sha := range strings.Fields(shas) {
		paths, err := gitOut(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
		if err != nil {
			return err
		}
		cycle = append(cycle, CycleCommit{SHA: sha, Paths: strings.Fields(paths)})
	}
	if problems := CheckRebaseOrder(cycle, filepath.ToSlash(rel)); len(problems) > 0 {
		return fmt.Errorf("%s", OrderFailure(witness, problems))
	}
	return nil
}

func gitOut(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
