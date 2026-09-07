package main

// main.go — I/O for mint-reachability: read MINT-STATE.json, ask git what
// changed in each repo since its last MINTED commit, classify, print one
// line. With -record it writes the decision back into MINT-STATE.json.
//
// With -e2e-record it judges a STALE e2e record instead (THE-RECORD-ONLY-
// CLOSE, 2026-09-07): the wiki's witness-ui-e2e gate refuses a record whose
// trees have moved, and twice the move was three record-only commits that
// cannot change e2e behaviour. Re-running a 4-minute mint to re-prove an
// unchanged appliance is a treadmill; reading a stale record unexamined is a
// weakening. So the gate asks this classifier: the record's own heads are the
// left-hand side, every path changed since them in BOTH repositories is
// judged by the same no-reach set, and the record stands ONLY when every one
// is declared no-reach. One reaching path and the record is refused exactly
// as before. A record that is not green, not finished or not pinned to both
// heads is never judged at all — it is undecidable, which the caller must
// treat as refused.
//
// It never runs the mint and never skips it on its own: `make test-full`
// reads the exit code. 0 = SKIPPABLE, 10 = MINT REQUIRED, 1 = it could not
// decide (which the harness must treat as required — an undecidable
// classifier is not a licence to skip).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExitSkippable / ExitRequired / ExitUndecidable are the harness contract.
const (
	ExitSkippable   = 0
	ExitUndecidable = 1
	ExitRequired    = 10
)

// MintState is the committed marker. It answers one question — which commit
// of each repo the last GREEN mint actually covered — because without it
// "the diff since the last mint" has no left-hand side.
type MintState struct {
	SchemaVersion string            `json:"schema_version"`
	LastMinted    map[string]string `json:"last_minted"`
	LastDecision  *Recorded         `json:"last_decision,omitempty"`
}

// Recorded is the audit trail the ruling demands: a skip that does not say
// what justified it does not exist.
type Recorded struct {
	At           string            `json:"at"`
	Mint         string            `json:"mint"`
	Repos        map[string]string `json:"repos"`
	JustifiedBy  map[string]string `json:"justified_by,omitempty"`
	ReachingWere []string          `json:"reaching_paths,omitempty"`
}

const stateSchema = "mint-state.v1"

func main() {
	repo := flag.String("repo", ".", "this repository root")
	sibling := flag.String("sibling", "../identuum-ui", "the sibling repository the mint also exercises")
	statePath := flag.String("state", "MINT-STATE.json", "the committed last-minted marker")
	record := flag.String("record", "", "record the outcome: skipped | minted")
	e2eRecord := flag.String("e2e-record", "", "judge a stale e2e record instead: accept it only when every path changed since its heads, in this repo and the sibling, is declared no-reach")
	flag.Parse()

	siblingDir := *sibling
	if !filepath.IsAbs(siblingDir) {
		siblingDir = filepath.Join(*repo, siblingDir)
	}

	if *e2eRecord != "" {
		os.Exit(judgeE2ERecord(*e2eRecord, *repo, siblingDir))
	}

	full := filepath.Join(*repo, *statePath)
	st, err := loadState(full)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check FAILED: mint-reachability —", err)
		os.Exit(ExitUndecidable)
	}

	repos := map[string]string{"identuum-idp-oss": *repo, "identuum-ui": siblingDir}
	var changed []string
	heads := map[string]string{}
	for name, dir := range repos {
		base, ok := st.LastMinted[name]
		if !ok || strings.TrimSpace(base) == "" {
			fmt.Fprintf(os.Stderr, "check FAILED: mint-reachability — %s has no last_minted commit in %s; the mint must run and record one\n", name, *statePath)
			os.Exit(ExitUndecidable)
		}
		head, err := gitOut(dir, "rev-parse", "HEAD")
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: mint-reachability — %s: %v\n", name, err)
			os.Exit(ExitUndecidable)
		}
		heads[name] = head
		files, err := changedSince(dir, base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check FAILED: mint-reachability — %s: %v\n", name, err)
			os.Exit(ExitUndecidable)
		}
		// Namespace the sibling's paths so a report can never confuse
		// which repository a file came from.
		for _, f := range files {
			if name == "identuum-idp-oss" {
				changed = append(changed, f)
			} else {
				changed = append(changed, name+"/"+f)
			}
		}
	}

	d := Decide(changed, NoReachSet)
	fmt.Println(d.Line())

	if *record != "" {
		if err := recordOutcome(full, st, *record, heads, d); err != nil {
			fmt.Fprintln(os.Stderr, "check FAILED: mint-reachability — recording:", err)
			os.Exit(ExitUndecidable)
		}
	}
	if d.Required {
		os.Exit(ExitRequired)
	}
	os.Exit(ExitSkippable)
}

// E2EHeads are the two commits a finished e2e record pins: the ui's own
// `repo-head:` and the `xrepo: identuum-idp-oss head=…` sibling pin.
type E2EHeads struct {
	UI      string
	Sibling string
}

// parseE2ERecord reads the heads out of a gate-run.v1 record and refuses
// anything that is not a green, finished record pinned to both heads. The
// refusal matters more than the parse: this function is reached only after
// achta's witness check has already FAILED the record, and staleness is the
// one failure this tool may look past. Red, incomplete or unpinned it may not.
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

func loadState(path string) (*MintState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (the mint must run once and record the commit it covered)", path, err)
	}
	var st MintState
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.SchemaVersion != stateSchema {
		return nil, fmt.Errorf("%s: schema_version %q, want %q", path, st.SchemaVersion, stateSchema)
	}
	if len(st.LastMinted) == 0 {
		return nil, errors.New("last_minted is empty")
	}
	return &st, nil
}

// recordOutcome writes the decision back. A skip records the FILE LIST that
// justified it; a mint moves last_minted forward.
func recordOutcome(path string, st *MintState, outcome string, heads map[string]string, d Decision) error {
	rec := &Recorded{
		At:    time.Now().UTC().Format(time.RFC3339),
		Mint:  outcome,
		Repos: heads,
	}
	switch outcome {
	case "skipped":
		if d.Required {
			return errors.New("refusing to record a skip for a change set that REQUIRES the mint")
		}
		rec.JustifiedBy = d.NoReach
	case "minted":
		rec.ReachingWere = d.Reaching
		for name, head := range heads {
			st.LastMinted[name] = head
		}
	default:
		return fmt.Errorf("unknown outcome %q (want skipped|minted)", outcome)
	}
	st.LastDecision = rec
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
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
