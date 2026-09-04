// Package main — witness-earns (THE-UNEARNED-WITNESS, 2026-09-04).
//
// A witness commit says "make verify was green on THIS tree". Cutting one
// costs a full verify, so it should only be cut when the tree actually
// changed in a way a verify can judge.
//
// MEASURED FIRST, from this repository's own history: 50 witness commits,
// 49 of which followed real work, and NINE record-only commits — eight
// manifest re-bases and one mint marker — each of which moved the tree and
// so demanded a fresh verify to be witnessed again. One witness cycle was
// entirely unearned: its whole diff was MINT-STATE.json plus a re-based
// ledger-amendments.json, changing no ledger row and no byte the appliance
// runs.
//
// THE CLASS: a record committed into the thing it measures can never be
// current. The mint marker showed it too — committing MINT-STATE.json made
// every mint invalidate the record it had just produced (P-052).
//
// RECORDS ARE EVIDENCE; EVIDENCE DOES NOT EARN A CYCLE. This refuses a
// witness whose diff since the previous witness touches only record paths,
// and it refuses ACTIONABLY: it names the paths and says what to do
// instead, because a gate that only says no teaches nothing.
//
// It does NOT relax anything. A witness still requires a green verify at a
// clean head; this only declines to spend one where there is nothing new to
// witness.
//
// Rule WITNESS-EARNS-ITS-CYCLE-1 binds to earns_test.go.
package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// RecordPaths are written BY the gates and the harness, and are read as
// evidence. None of them is compiled, served, or judged by any check: a
// change confined to them cannot alter what a verify would conclude.
var RecordPaths = []string{
	"GATE-RUN*.txt",          // every gate record, committed or not
	"ledger-amendments.json", // the manifest — its base field moves per cycle
	"MINT-STATE.json",        // the mint marker (gitignored since P-052)
}

// Verdict is the answer plus everything the message needs.
type Verdict struct {
	Earned      bool
	Changed     []string
	RecordOnly  []string
	Substantive []string
}

// Decide judges a change set. An empty one is NOT earned — nothing changed,
// so the previous witness already covers this tree.
func Decide(changed []string) Verdict {
	v := Verdict{Changed: append([]string(nil), changed...)}
	sort.Strings(v.Changed)
	for _, p := range v.Changed {
		if isRecord(p) {
			v.RecordOnly = append(v.RecordOnly, p)
			continue
		}
		v.Substantive = append(v.Substantive, p)
	}
	v.Earned = len(v.Substantive) > 0
	return v
}

func isRecord(p string) bool {
	p = strings.TrimPrefix(path.Clean(p), "./")
	base := path.Base(p)
	for _, pat := range RecordPaths {
		if ok, err := path.Match(pat, base); err == nil && ok && base == p {
			return true
		}
	}
	return false
}

// Line is what the caller prints. The `check OK:` prefix is the gate-witness
// evidence pattern; a refusal deliberately does NOT wear it.
func (v Verdict) Line() string {
	if v.Earned {
		return fmt.Sprintf("check OK: witness-earns EARNED — %d substantive path(s) since the last witness: %s",
			len(v.Substantive), strings.Join(clip(v.Substantive, 6), ", "))
	}
	if len(v.Changed) == 0 {
		return "witness-earns REFUSES: nothing has changed since the last witness — this tree is ALREADY WITNESSED. " +
			"Do not cut another cycle; the standing witness covers it."
	}
	return fmt.Sprintf(
		"witness-earns REFUSES: everything changed since the last witness is a RECORD — %s. "+
			"Records are evidence, and evidence does not earn a cycle: this tree is ALREADY WITNESSED "+
			"in everything a verify can judge. Fold these into the next work commit instead of spending "+
			"a verify on them; if you genuinely need the record committed now, it rides with that commit.",
		strings.Join(v.RecordOnly, ", "))
}

func clip(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("…and %d more", len(s)-n))
}
