package main

// main.go — I/O for witness-earns: ask git what changed since the previous
// witness commit, judge it, print one line. Exit 0 when the cycle is
// earned, 11 when it is refused, 1 when it cannot tell (which the caller
// must treat as "go ahead and witness" — this check exists to save a cycle,
// never to block one it cannot reason about).

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// WitnessSubject is the same subject line ledger-diff-gate keys on.
const WitnessSubject = "Witness: make verify green at "

const (
	ExitEarned  = 0
	ExitUnknown = 1
	ExitRefused = 11
)

func main() {
	repo := flag.String("repo", ".", "repository root")
	flag.Parse()

	base, err := gitOut(*repo, "log", "--format=%H", "-1", "--fixed-strings", "--grep="+WitnessSubject, "HEAD")
	if err != nil || strings.TrimSpace(base) == "" {
		fmt.Fprintln(os.Stderr, "witness-earns: no witness commit in history yet — nothing to compare against, so the cycle stands")
		os.Exit(ExitUnknown)
	}
	changed, err := changedSince(*repo, strings.TrimSpace(base))
	if err != nil {
		fmt.Fprintln(os.Stderr, "witness-earns: cannot read the diff:", err)
		os.Exit(ExitUnknown)
	}
	v := Decide(changed)
	if v.Earned {
		fmt.Println(v.Line())
		os.Exit(ExitEarned)
	}
	fmt.Fprintln(os.Stderr, v.Line())
	os.Exit(ExitRefused)
}

// changedSince lists paths changed between base and HEAD plus anything
// uncommitted — the tree a witness would name is the tree as it stands.
func changedSince(dir, base string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, args := range [][]string{
		{"diff", "--name-only", base + "..HEAD"},
		{"status", "--porcelain"},
	} {
		out, err := gitOut(dir, args...)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if args[0] == "status" {
				if len(line) > 3 {
					line = strings.TrimSpace(line[2:])
				}
				if i := strings.LastIndex(line, " -> "); i >= 0 {
					line = line[i+4:]
				}
			}
			seen[line] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func gitOut(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}
