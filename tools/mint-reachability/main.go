package main

// main.go — I/O for mint-reachability: read MINT-STATE.json, ask git what
// changed in each repo since its last MINTED commit, classify, print one
// line. With -record it writes the decision back into MINT-STATE.json.
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
	flag.Parse()

	full := filepath.Join(*repo, *statePath)
	st, err := loadState(full)
	if err != nil {
		fmt.Fprintln(os.Stderr, "check FAILED: mint-reachability —", err)
		os.Exit(ExitUndecidable)
	}

	repos := map[string]string{"identuum-idp-oss": *repo, "identuum-ui": filepath.Join(*repo, *sibling)}
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
