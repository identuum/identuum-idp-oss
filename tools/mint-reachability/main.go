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
// declared no-reach — or, since GATE-TIERS (2026-09-26), when every reaching
// one is quick-class and a green GATE-RUN.e2e-quick.txt pins these trees.
//
// GATE-TIERS: a required mint names its tier (reach.go). A full-tier change
// is paid only by a new e2e-full record; a quick-tier change also by a green
// e2e-quick record beside it whose heads are these trees' — consulted only
// when the decision is quick. A quick record is never read as the e2e-full
// record. Comment-only deployment YAML is judged none by its diff's content
// and its parsed value, before classification.
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
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
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
	proveNoReach := flag.Bool("prove-no-reach", false, "only prove that no declared gate program is in the appliance's build closure (go list -deps ./cmd/...); exit 0 with the proof line, 1 naming the reachable program")
	flag.Parse()

	siblingDir := *sibling
	if !filepath.IsAbs(siblingDir) {
		siblingDir = filepath.Join(*repo, siblingDir)
	}

	if *proveNoReach {
		line, err := ProveGateProgramsUnreachable(*repo)
		if err != nil {
			fmt.Fprintln(os.Stderr, "check FAILED: mint-reachability —", err)
			os.Exit(ExitUndecidable)
		}
		fmt.Println(line)
		os.Exit(ExitSkippable)
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
	if heads.Quick() {
		return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s was written by e2e-quick (%s): a quick record pays the quick tier only, never the e2e-full mint", name, heads.Gate), ExitRequired
	}
	d, line, code := judgeSince(name, heads, repoDir, uiDir)
	if code != ExitSkippable {
		return line, code
	}
	since := fmt.Sprintf("(since %s: identuum-ui %s, identuum-idp-oss %s)", name, heads.UI, heads.Sibling)
	switch d.Tier {
	case TierFull:
		return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s %s", d.Summary(), since), ExitRequired
	case TierQuick:
		// GATE-TIERS: the quick tier is paid only by a green e2e-quick record
		// pinned to THESE trees — nothing reaching since its own heads. It is
		// read here and nowhere else: only a quick decision consults it.
		qpath := filepath.Join(filepath.Dir(recordPath), quickRecordName)
		qline, ok := quickPays(qpath, repoDir, uiDir)
		if !ok {
			return fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s %s; e2e-quick owed: %s", d.Summary(), since, qline), ExitRequired
		}
		if line, code := proofsHold(d, repoDir, uiDir); code != ExitSkippable {
			return line, code
		}
		return fmt.Sprintf("check OK: mint-reachability MINT SATISFIED by %s — %s %s", qline, d.Summary(), since), ExitSkippable
	}
	if line, code := proofsHold(d, repoDir, uiDir); code != ExitSkippable {
		return line, code
	}
	return fmt.Sprintf("check OK: mint-reachability MINT SATISFIED by %s (identuum-ui %s, identuum-idp-oss %s) — %s",
		name, heads.UI, heads.Sibling, d.Summary()), ExitSkippable
}

// quickRecordName is e2e-quick's record, beside the e2e-full one in the
// sibling checkout (gitignored there, never tracked).
const quickRecordName = "GATE-RUN.e2e-quick.txt"

// judgeSince checks that the record's two heads are in the judged trees'
// histories and classifies every path changed since them — comment-only
// deployment YAML set aside by content first. A non-Skippable code means the
// question could not be put: the line says why.
func judgeSince(name string, heads E2EHeads, repoDir, uiDir string) (Decision, string, int) {
	var changed, commentOnly []string
	for _, r := range []struct{ name, dir, base string }{
		{"identuum-ui", uiDir, heads.UI},
		{"identuum-idp-oss", repoDir, heads.Sibling},
	} {
		// The record must vouch for THESE trees: each pinned head has to be in
		// the history of the tree it names, or the record is some other tree's.
		if !isAncestor(r.dir, r.base) {
			head, _ := gitOut(r.dir, "rev-parse", "--short", "HEAD")
			return Decision{}, fmt.Sprintf("check OK: mint-reachability MINT REQUIRED — %s pins %s %s, which is not in the history of the %s tree being judged (HEAD %s): the record vouches for another tree",
				name, r.name, r.base, r.name, head), ExitRequired
		}
		files, err := changedSince(r.dir, r.base)
		if err != nil {
			return Decision{}, fmt.Sprintf("check FAILED: mint-reachability — %s since %s: %v", r.name, r.base, err), ExitUndecidable
		}
		kept, dropped := splitCommentOnlyYAML(r.dir, r.base, r.name, files)
		commentOnly = append(commentOnly, dropped...)
		// Namespace the sibling's paths so a report can never confuse which
		// repository a file came from.
		for _, f := range kept {
			if r.name == "identuum-idp-oss" {
				changed = append(changed, f)
			} else {
				changed = append(changed, r.name+"/"+f)
			}
		}
	}
	d := Decide(changed, NoReachSet)
	d.CommentOnly = commentOnly
	return d, "", ExitSkippable
}

// quickPays reports whether the e2e-quick record at path pays the quick tier
// for THESE trees: green, finished, written by e2e-quick, both heads in
// history, and nothing reaching since them. The line names the record or why
// it does not pay.
func quickPays(path, repoDir, uiDir string) (string, bool) {
	name := filepath.Base(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("no green %s at %s", name, path), false
	}
	heads, err := parseE2ERecord(string(raw))
	if err != nil {
		return fmt.Sprintf("%s does not pay: %v", name, err), false
	}
	if !heads.Quick() {
		return fmt.Sprintf("%s was not written by e2e-quick (%s)", name, heads.Gate), false
	}
	d, line, code := judgeSince(name, heads, repoDir, uiDir)
	if code != ExitSkippable {
		return fmt.Sprintf("%s does not pay: %s", name, line), false
	}
	if d.Required {
		return fmt.Sprintf("%s is stale — since its heads (identuum-ui %s, identuum-idp-oss %s): %s", name, heads.UI, heads.Sibling, d.Summary()), false
	}
	if line, code := proofsHold(d, repoDir, uiDir); code != ExitSkippable {
		return fmt.Sprintf("%s does not pay: %s", name, line), false
	}
	return fmt.Sprintf("%s (identuum-ui %s, identuum-idp-oss %s)", name, heads.UI, heads.Sibling), true
}

// proofsHold re-proves, on THIS tree, every declaration d relied on that
// rests on a proof: a gate-program entry or the sibling's Makefile. If a
// proof cannot run or fails, the answer is undecidable, which the harness
// treats as MINT REQUIRED.
func proofsHold(d Decision, repoDir, uiDir string) (string, int) {
	if reliesOnGateProgram(d) {
		if _, err := ProveGateProgramsUnreachable(repoDir); err != nil {
			return fmt.Sprintf("check FAILED: mint-reachability — %v", err), ExitUndecidable
		}
	}
	if reliesOnSiblingMakefile(d) {
		if _, err := ProveSiblingMakefileUnreachable(uiDir); err != nil {
			return fmt.Sprintf("check FAILED: mint-reachability — %v", err), ExitUndecidable
		}
	}
	return "", ExitSkippable
}

// splitCommentOnlyYAML sets aside identuum-idp-oss deployment/**/*.yml|*.yaml
// paths whose change since base is comment-only, judged by CONTENT, never by
// name: every line the diff adds or removes is blank or a # comment, AND the
// file parses to the same YAML value before and after — a '#' line inside a
// block scalar is data, and the parse catches it. A new, deleted, renamed or
// mode-changed file, a parse error or any git error keeps the path (fail
// closed).
func splitCommentOnlyYAML(dir, base, repo string, files []string) (kept, dropped []string) {
	for _, f := range files {
		if repo == "identuum-idp-oss" && strings.HasPrefix(f, "deployment/") &&
			(strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml")) && commentOnlyYAML(dir, base, f) {
			dropped = append(dropped, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

func commentOnlyYAML(dir, base, f string) bool {
	diff, err := gitOut(dir, "diff", "-U0", base, "--", f)
	if err != nil || !strings.Contains(diff, "@@") {
		return false
	}
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "new file"), strings.HasPrefix(line, "deleted file"),
			strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "old mode"), strings.HasPrefix(line, "new mode"):
			return false
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			continue
		case strings.HasPrefix(line, "+"), strings.HasPrefix(line, "-"):
			if c := strings.TrimSpace(line[1:]); c != "" && !strings.HasPrefix(c, "#") {
				return false
			}
		}
	}
	before, err := gitOut(dir, "show", base+":"+f)
	if err != nil {
		return false
	}
	after, err := os.ReadFile(filepath.Join(dir, f))
	if err != nil {
		return false
	}
	var old, cur any
	if yaml.Unmarshal([]byte(before), &old) != nil || yaml.Unmarshal(after, &cur) != nil {
		return false
	}
	return reflect.DeepEqual(old, cur)
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
	// Gate is the record's `gate:` line: which harness mode wrote it.
	Gate string
}

// Quick reports whether e2e-quick wrote the record.
func (h E2EHeads) Quick() bool { return strings.HasSuffix(h.Gate, "make e2e-quick") }

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
		case strings.HasPrefix(line, "gate: "):
			h.Gate = strings.TrimSpace(strings.TrimPrefix(line, "gate: "))
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
	if heads.Quick() {
		fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %s was written by e2e-quick (%s): a quick record is never the e2e-full record\n", filepath.Base(recordPath), heads.Gate)
		return ExitUndecidable
	}
	// Each repository is judged on its own range and says so on its own
	// line, so a reader sees WHICH tree moved and on what; the verdict is
	// over the union, because the record pins both.
	var changed, commentOnly []string
	for _, r := range []struct{ name, dir, base string }{
		{"identuum-ui", uiDir, heads.UI},
		{"identuum-idp-oss", repoDir, heads.Sibling},
	} {
		files, err := changedSince(r.dir, r.base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %s since %s: %v\n", r.name, r.base, err)
			return ExitUndecidable
		}
		kept, dropped := splitCommentOnlyYAML(r.dir, r.base, r.name, files)
		commentOnly = append(commentOnly, dropped...)
		var named []string
		for _, f := range kept {
			if r.name == "identuum-idp-oss" {
				named = append(named, f)
			} else {
				named = append(named, r.name+"/"+f)
			}
		}
		one := Decide(named, NoReachSet)
		one.CommentOnly = dropped
		fmt.Printf("e2e-record: %s %s..HEAD — %s\n", r.name, r.base, one.Summary())
		changed = append(changed, named...)
	}
	d := Decide(changed, NoReachSet)
	d.CommentOnly = commentOnly
	fmt.Printf("e2e-record: %s was minted at identuum-ui %s and identuum-idp-oss %s; %d path(s) changed since, in the two trees, judged by the no-reach set\n",
		filepath.Base(recordPath), heads.UI, heads.Sibling, len(d.Changed))
	fmt.Println(d.Line())
	if d.Tier == TierFull {
		fmt.Printf("check FAILED: e2e-record-reach REFUSED — the stale record cannot stand for this tree: %d reaching path(s) since its heads, %d of them full-class; mint a new e2e-full\n", len(d.Reaching), len(d.Full))
		return ExitRequired
	}
	if d.Tier == TierQuick {
		// GATE-TIERS: every reaching path is quick-class — the stale e2e-full
		// record stands only beside a green e2e-quick record for THESE trees.
		qline, ok := quickPays(filepath.Join(filepath.Dir(recordPath), quickRecordName), repoDir, uiDir)
		if !ok {
			fmt.Printf("check FAILED: e2e-record-reach REFUSED — %d quick-class path(s) since its heads and no e2e-quick record pays them: %s; mint e2e-quick\n", len(d.Reaching), qline)
			return ExitRequired
		}
		fmt.Printf("e2e-record: the quick tier is paid by %s\n", qline)
	}
	// The same proof obligation as the mint decision: an excuse resting on
	// a gate-program entry stands only while the entry is provably sound.
	if reliesOnGateProgram(d) {
		line, err := ProveGateProgramsUnreachable(repoDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %v\n", err)
			return ExitUndecidable
		}
		fmt.Println(line)
	}
	if reliesOnSiblingMakefile(d) {
		line, err := ProveSiblingMakefileUnreachable(uiDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: e2e-record-reach — %v\n", err)
			return ExitUndecidable
		}
		fmt.Println(line)
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
