// Package main — ci-witness (THE-UNRUN-CI, 2026-09-04).
//
// WHY THIS EXISTS
// ---------------
// Three slices in a row ended with "CI cannot be run from here", and the
// stale GATE_WITNESS_SHA256 proved what that costs: CI can sit broken for
// two slices while every local gate is green. The gap is not that CI is
// unreliable — it is that NOTHING HERE CARRIES A CI RESULT. `make verify`
// witnesses a local run into a committed GATE-RUN.txt. A CI run produces the
// same kind of record (GATE-RUN.ci.txt, written by the same gate-witness
// under GATE_WITNESS_TIE=commit) and then uploads it to an artifact nobody
// downloads, so no local gate has ever seen one.
//
// This gate is the local half of closing that. It does not fetch anything —
// a gate that reaches the network is a gate that fails on a plane — and it
// cannot make CI run. It judges a CI record IF ONE IS COMMITTED HERE:
//
//	ABSENT   → pass, and SAY SO: "no CI record; nothing here evidences a
//	           CI run". Absence is honest. Silence that reads like a pass
//	           is what this whole slice is about.
//	PRESENT  → it must be green, COMPLETE (every planned target recorded
//	           exit=0), tied by COMMIT (a digest tie is a local record
//	           wearing a CI name), clean at finalize, and it must name a
//	           commit THIS repository actually contains on HEAD's ancestry.
//	           Anything else FAILS.
//
// A record that is behind HEAD does NOT fail — CI runs on push and local
// work moves on, so "behind" is the normal state and failing it would push
// people to delete the record instead of reading it. The distance is
// REPORTED instead, in the evidence line, so a reader always knows which
// tree the CI claim covers.
//
// Rule CI-RECORD-HONEST-1 binds to judge_test.go.
package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var commitTieRe = regexp.MustCompile(`^tree: commit=([0-9a-f]{40})(.*)$`)

// Record is the subset of a gate-witness record this gate judges.
type Record struct {
	Present bool
	// Tracked: the record is COMMITTED here. An untracked file is a scratch
	// file, not a claim — GATE-RUN.ci.txt is gitignored precisely so a local
	// `make ci-verify` can leave one behind without asserting anything.
	Tracked bool
	// RunRef is the provenance line only the workflow can write (`ci-run:`
	// with the run URL). Written by CI, never by a local run.
	RunRef string
	// Plan is the declared target set; Targets is what actually recorded.
	Plan    []string
	Targets map[string]int
	Result  string
	// CommitTie is set only for a CI-shaped record (GATE_WITNESS_TIE=commit).
	CommitTie string
	// DigestTie is true when the record ties by content digest instead —
	// the LOCAL shape, which cannot vouch for a CI run.
	DigestTie       bool
	DirtyAtFinalize bool
	Label           string
}

// Ancestry is what git says about the commit the record names.
type Ancestry struct {
	// Known: the commit object exists in this repository at all.
	Known bool
	// IsAncestor: it is HEAD or an ancestor of HEAD.
	IsAncestor bool
	// Behind: how many commits HEAD is ahead of it.
	Behind int
}

// Judge decides. The summary is the one line gate-witness records; the
// `check OK:` prefix is the evidence pattern, so the absent case must earn
// it honestly — by stating that nothing is claimed.
func Judge(r Record, a Ancestry) (summary string, ok bool) {
	// NO CLAIM. Absent, or present-but-untracked: either way nothing here
	// asserts a CI run, and the honest answer is to say so.
	//
	// The untracked case is not hypothetical and it is why this gate does
	// not trust a commit tie on its own. A LOCAL `make ci-verify` writes the
	// same record, with the same `gate:` label, into the same gitignored
	// path — one from 2026-08-28 was sitting in this working tree, green and
	// commit-tied, 138 commits behind HEAD, and the first version of this
	// gate accepted it as CI evidence. Nothing in the bytes distinguished it
	// from a downloaded artifact. So: committed, or it is not a claim.
	if !r.Present {
		return "check OK: ci-witness NO CI RECORD — nothing here evidences a CI run; the workflow's declarations remain declared, unrun", true
	}
	if !r.Tracked {
		return "check OK: ci-witness NO CI CLAIM — a record exists but is UNTRACKED (a local `make ci-verify` writes the same file to the same gitignored path); an uncommitted record asserts nothing, so CI remains declared, unrun", true
	}

	var problems []string
	// Provenance first: a committed record that cannot say which run produced
	// it is a claim nobody can check, and a local run can forge everything
	// else in the file.
	if strings.TrimSpace(r.RunRef) == "" {
		problems = append(problems, "the record is committed but carries NO `ci-run:` provenance — nothing in it distinguishes a CI artifact from a local `make ci-verify`, so it cannot witness CI")
	}
	if r.DigestTie && r.CommitTie == "" {
		problems = append(problems, "the record ties by content digest, not by commit — that is a LOCAL record, and a local record cannot witness CI")
	}
	if r.CommitTie == "" && !r.DigestTie {
		problems = append(problems, "no tie line at all: the record names no tree, so it evidences nothing")
	}
	if r.DirtyAtFinalize {
		problems = append(problems, "the record was finalized on a DIRTY tree, so the commit it names is not the tree that ran")
	}
	if r.Result != "green" {
		problems = append(problems, fmt.Sprintf("result is %q, not green", orNone(r.Result)))
	}
	// Completeness: a record may only claim what it recorded.
	if len(r.Plan) == 0 {
		problems = append(problems, "the record declares an EMPTY plan — a run that planned nothing proves nothing")
	}
	var unrun []string
	for _, name := range r.Plan {
		code, recorded := r.Targets[name]
		if !recorded {
			unrun = append(unrun, name+" (never recorded)")
			continue
		}
		if code != 0 {
			unrun = append(unrun, fmt.Sprintf("%s (exit=%d)", name, code))
		}
	}
	if len(unrun) > 0 {
		problems = append(problems, "planned targets that did not pass: "+strings.Join(unrun, ", "))
	}
	if r.CommitTie != "" {
		switch {
		case !a.Known:
			problems = append(problems, "commit "+short(r.CommitTie)+" is not in this repository — a record naming a commit this checkout does not contain is not evidence about this tree")
		case !a.IsAncestor:
			problems = append(problems, "commit "+short(r.CommitTie)+" is not on HEAD's ancestry — it witnesses a different line of history")
		}
	}

	if len(problems) > 0 {
		return "check FAILED: ci-witness — " + strings.Join(problems, "; "), false
	}

	// Behind is reported, never failed: CI runs on push, local work moves on.
	where := "at HEAD"
	if a.Behind > 0 {
		where = fmt.Sprintf("%d commit(s) behind HEAD — the CI claim covers that tree, not this one", a.Behind)
	}
	return fmt.Sprintf("check OK: ci-witness %s green, %d planned target(s) all exit=0, ties commit %s, %s, run %s",
		orNone(r.Label), len(r.Plan), short(r.CommitTie), where, r.RunRef), true
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

// ParseRecord reads a gate-witness record. Anything it cannot find stays
// zero, and Judge fails on the zero values rather than passing.
func ParseRecord(raw []byte) Record {
	r := Record{Present: true, Targets: map[string]int{}}
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "gate: "):
			r.Label = strings.TrimSpace(strings.TrimPrefix(line, "gate: "))
		case strings.HasPrefix(line, "plan: "):
			if len(r.Plan) == 0 {
				r.Plan = strings.Fields(strings.TrimPrefix(line, "plan: "))
			}
		case strings.HasPrefix(line, "target: "):
			rest := strings.TrimPrefix(line, "target: ")
			name, code, found := strings.Cut(rest, " exit=")
			if !found {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(code))
			if err != nil {
				continue
			}
			r.Targets[strings.TrimSpace(name)] = n
		case strings.HasPrefix(line, "result: "):
			r.Result = strings.TrimSpace(strings.TrimPrefix(line, "result: "))
		case strings.HasPrefix(line, "ci-run: "):
			r.RunRef = strings.TrimSpace(strings.TrimPrefix(line, "ci-run: "))
		case strings.HasPrefix(line, "tree: sha256="):
			r.DigestTie = true
		case strings.HasPrefix(line, "tree: commit="):
			if m := commitTieRe.FindStringSubmatch(line); m != nil {
				r.CommitTie = m[1]
				if strings.Contains(m[2], "dirty") {
					r.DirtyAtFinalize = true
				}
			} else {
				// `tree: commit=none`, or anything malformed: no usable tie.
				r.DirtyAtFinalize = strings.Contains(line, "dirty")
			}
		}
	}
	return r
}
