package main

// main.go — I/O for ci-witness: reads the CI record if it exists, asks git
// about the commit it names, prints ONE line. It fetches nothing and fixes
// nothing.

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	repo := flag.String("repo", ".", "repository root")
	record := flag.String("record", "GATE-RUN.ci.txt", "the CI gate record, if one has been committed here")
	flag.Parse()

	raw, err := os.ReadFile(filepath.Join(*repo, *record))
	var r Record
	switch {
	case err == nil:
		r = ParseRecord(raw)
		r.Label = orLabel(r.Label, *record)
		// Committed, or it is not a claim.
		r.Tracked = git(*repo, "ls-files", "--error-unmatch", *record) == nil
	case os.IsNotExist(err):
		r = Record{Present: false}
	default:
		fmt.Fprintln(os.Stderr, "check FAILED: ci-witness — cannot read", *record, ":", err)
		os.Exit(1)
	}

	summary, ok := Judge(r, ancestry(*repo, r.CommitTie))
	if !ok {
		fmt.Fprintln(os.Stderr, summary)
		os.Exit(1)
	}
	fmt.Println(summary)
}

func orLabel(label, fallback string) string {
	if strings.TrimSpace(label) == "" {
		return fallback
	}
	return label
}

// ancestry asks git what it knows about the commit the record names.
func ancestry(repo, sha string) Ancestry {
	if sha == "" {
		return Ancestry{}
	}
	if git(repo, "cat-file", "-e", sha+"^{commit}") != nil {
		return Ancestry{}
	}
	a := Ancestry{Known: true}
	a.IsAncestor = git(repo, "merge-base", "--is-ancestor", sha, "HEAD") == nil
	if a.IsAncestor {
		if out, err := gitOut(repo, "rev-list", "--count", sha+"..HEAD"); err == nil {
			a.Behind, _ = strconv.Atoi(strings.TrimSpace(out))
		}
	}
	return a
}

func git(repo string, args ...string) error {
	return exec.Command("git", append([]string{"-C", repo}, args...)...).Run()
}

func gitOut(repo string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	return string(out), err
}
