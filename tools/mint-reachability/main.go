package main

// main.go — I/O for mint-reachability: read the mint's own record, ask git
// what changed in each repo since the heads that record pins, classify, print
// one line.
//
// THE-ONE-MINT-RECORD (2026-09-12): the mint has ONE record of record — the
// gate-run record identuum-ui's e2e-full run writes (GATE-RUN.e2e-full.txt in
// the sibling checkout), carrying its own head, the identuum-idp-oss head and
// tree digest it exercised, and its result. Until this slice the decision
// read a second writer instead, MINT-STATE.json, written only by this
// repository's test-full target — so three mints paid from identuum-ui moved
// the record and never the marker, and the marker sat two slices and three
// mints behind the record the wiki's judge already trusted. Two writers were
// the defect; the marker is retired. A paid mint is SATISFIED only by a green,
// finished record whose two heads are in the judged trees' histories and
// since which every changed path is declared no-reach. An ABSENT record is
// MINT REQUIRED: nothing says a mint was ever paid for this checkout. A RED
// record is MINT REQUIRED: a red record is not a mint. A head outside the
// judged tree is MINT REQUIRED: the record vouches for some other tree. The
// rule that decides WHETHER a change reaches the appliance (reach.go,
// MINT-REACHABILITY-1) is untouched — this file changes only how "already
// paid" is established.
//
// With -e2e-record it judges a STALE e2e record for the wiki's witness-ui-e2e
// gate (THE-RECORD-ONLY-CLOSE, 2026-09-07) by the same set: the record's own
// heads are the left-hand side, every path changed since them in BOTH
// repositories is judged, and the record stands ONLY when every one is
// declared no-reach. That mode is unchanged.
//
// It never runs the mint and never skips it on its own: `make test-full`
// reads the exit code. 0 = SATISFIED (skippable), 10 = MINT REQUIRED, 1 = it
// could not decide (which the harness must treat as required — an undecidable
// classifier is not a licence to skip).

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// ExitSkippable / ExitRequired / ExitUndecidable are the harness contract.
const (
	ExitSkippable   = 0
	ExitUndecidable = 1
	ExitRequired    = 10
)

// defaultRecord is the mint's record of record, relative to the sibling
// checkout that produces it. It is gitignored there and never tracked.
const defaultRecord = "GATE-RUN.e2e-full.txt"

func main() {
	repo := flag.String("repo", ".", "this repository root")
	sibling := flag.String("sibling", "../identuum-ui", "the sibling repository the mint also exercises")
	recordName := flag.String("mint-record", defaultRecord, "the mint's record of record, relative to the sibling checkout")
	e2eRecord := flag.String("e2e-record", "", "judge a stale e2e record instead: accept it only when every path changed since its heads, in this repo and the sibling, is declared no-reach")
	flag.Parse()

	siblingDir := *sibling
	if !filepath.IsAbs(siblingDir) {
		siblingDir = filepath.Join(*repo, siblingDir)
	}

	if *e2eRecord != "" {
		os.Exit(judgeE2ERecord(*e2eRecord, *repo, siblingDir))
	}

	recordPath := *recordName
	if !filepath.IsAbs(recordPath) {
		recordPath = filepath.Join(siblingDir, recordPath)
	}
	line, code := decideFromRecord(recordPath, *repo, siblingDir)
	if code == ExitUndecidable {
		fmt.Fprintln(os.Stderr, line)
	} else {
		fmt.Println(line)
	}
	os.Exit(code)
}

// decideFromRecord answers "is a mint owed for these two trees?" from the
// mint's own record and nothing else. It returns the one evidence line and
// the exit code of the harness contract.
func decideFromRecord(recordPath, repoDir, uiDir string) (string, int) {
	name := filepath.Base(recordPath)
	raw, err := os.ReadFile(recordPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — no e2e record at %s: nothing says a mint was ever paid for this checkout", recordPath), ExitRequired
	case err != nil:
		return fmt.Sprintf("check FAILED: mint-reachability — %s: %v", name, err), ExitUndecidable
	}
	heads, err := parseE2ERecord(string(raw))
	if err != nil {
		if strings.Contains(err.Error(), "not green") {
			return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s is not green: a red record is not a mint", name), ExitRequired
		}
		return fmt.Sprintf("check FAILED: mint-reachability — %s: %v", name, err), ExitUndecidable
	}
	// The record must vouch for THESE trees: each pinned head has to be in
	// the history of the tree it names, or the record is some other tree's.
	var changed []string
	for _, r := range []struct{ name, dir, base string }{
		{"identuum-ui", uiDir, heads.UI},
		{"identuum-idp-oss", repoDir, heads.Sibling},
	} {
		if !isAncestor(r.dir, r.base) {
			head, _ := gitOut(r.dir, "rev-parse", "--short", "HEAD")
			return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s pins %s %s, which is not in the history of the %s tree being judged (HEAD %s): the record vouches for another tree",
				name, r.name, r.base, r.name, head), ExitRequired
		}
		files, err := changedSince(r.dir, r.base)
		if err != nil {
			return fmt.Sprintf("check FAILED: mint-reachability — %s since %s: %v", r.name, r.base, err), ExitUndecidable
		}
		// Namespace the sibling's paths so a report can never confuse which
		// repository a file came from.
		for _, f := range files {
			if r.name == "identuum-idp-oss" {
				changed = append(changed, f)
			} else {
				changed = append(changed, r.name+"/"+f)
			}
		}
	}
	d := Decide(changed, NoReachSet)
	if d.Required {
		return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s (since %s: identuum-ui %s, identuum-idp-oss %s)",
			d.Summary(), name, heads.UI, heads.Sibling), ExitRequired
	}
	return fmt.Sprintf("check OK: mint-reachability MINT SATISFIED by %s (identuum-ui %s, identuum-idp-oss %s) — %s",
		name, heads.UI, heads.Sibling, d.Summary()), ExitSkippable
}

// isAncestor reports whether base is in the history of dir's HEAD. An
// unknown or malformed revision is simply not an ancestor.
func isAncestor(dir, base string) bool {
	cmd := exec.Command("git", "-C", dir, "merge-base", "--is-ancestor", base, "HEAD")
	return cmd.Run() == nil
}

// E2EHeads are the two commits a finished e2e record pins: the ui's own
// `repo-head:` and the `xrepo: identuum-idp-oss head=…` sibling pin.
type E2EHeads struct {
	UI      string
	Sibling string
}

// parseE2ERecord reads the heads out of a gate-run.v1 record and refuses
// anything that is not a green, finished record pinned to both heads. The
// refusal matters more than the parse: in -e2e-record mode this function is
// reached only after achta's witness check has already FAILED the record, and
// staleness is the one failure this tool may look past. Red, incomplete or
// unpinned it may not — and the mint decision reads the same refusal.
func parseE2ERecord(text string) (E2EHeads, error) {
	var h E2EHeads
	green, finished := false, false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "repo-head: "):
			h.UI = strings.TrimSpace(strings.TrimPrefix(line, "repo-head: "))
		case strings.HasPrefix(line, "xrepo: identuum-idp-oss "):
			for _, f := range strings.Fields(strings.TrimPrefix(line, "xrepo: identuum-idp-oss ")) {
				if v, ok := strings.CutPrefix(f, "head="); ok {
					h.Sibling = v
				}
			}
		case strings.HasPrefix(line, "finished: "):
			finished = true
		case line == "result: green":
			green = true
		}
	}
	switch {
	case !green:
		return h, errors.New("the record is not green — a red record is refused, not judged")
	case !finished:
		return h, errors.New("the record has no finished: line — an incomplete record is refused, not judged")
	case h.UI == "":
		return h, errors.New("the record has no repo-head: line")
	case h.Sibling == "":
		return h, errors.New("the record has no xrepo: identuum-idp-oss head= pin")
	}
	return h, nil
}

// judgeE2ERecord is the -e2e-record mode. Undecidable is exit 1, refused is
// exit 10, accepted is exit 0 — the same contract as the mint decision, and
// every line says which repository a path came from.
func judgeE2ERecord(recordPath, repoDir, uiDir string) int {
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check FAILED: e2e-record-reach —", err)
		return ExitUndecidable
	}
	heads, err := parseE2ERecord(string(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %s: %v\n", filepath.Base(recordPath), err)
		return ExitUndecidable
	}
	// Each repository is judged on its own range and says so on its own
	// line, so a reader sees WHICH tree moved and on what; the verdict is
	// over the union, because the record pins both.
	var changed []string
	for _, r := range []struct{ name, dir, base string }{
		{"identuum-ui", uiDir, heads.UI},
		{"identuum-idp-oss", repoDir, heads.Sibling},
	} {
		files, err := changedSince(r.dir, r.base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %s since %s: %v\n", r.name, r.base, err)
			return ExitUndecidable
		}
		var named []string
		for _, f := range files {
			if r.name == "identuum-idp-oss" {
				named = append(named, f)
			} else {
				named = append(named, r.name+"/"+f)
			}
		}
		fmt.Printf("e2e-record: %s %s..HEAD — %s\n", r.name, r.base, Decide(named, NoReachSet).Summary())
		changed = append(changed, named...)
	}
	d := Decide(changed, NoReachSet)
	fmt.Printf("e2e-record: %s was minted at identuum-ui %s and identuum-idp-oss %s; %d path(s) changed since, in the two trees, judged by the no-reach set\n",
		filepath.Base(recordPath), heads.UI, heads.Sibling, len(d.Changed))
	fmt.Println(d.Line())
	if d.Required {
		fmt.Printf("check FAILED: e2e-record-reach REFUSED — the stale record cannot stand for this tree: %d reaching path(s) since its heads; mint a new e2e-full\n", len(d.Reaching))
		return ExitRequired
	}
	fmt.Printf("check OK: e2e-record-reach ACCEPTED — the record's claim stands: every path since identuum-ui %s and identuum-idp-oss %s is declared no-reach (record-only commits)\n", heads.UI, heads.Sibling)
	return ExitSkippable
}

// changedSince lists paths changed between base and HEAD, plus anything
// uncommitted — a dirty tree is part of what would ship.
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
				// "XY path" or "XY old -> new"
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
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}
