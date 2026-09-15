package main

// rebase.go — THE-MANIFEST-CADENCE (2026-09-03).
//
// WHY THIS EXISTS
// ---------------
// `base_commit` was hand-written, and it had to equal a value the gate
// ALREADY measures for itself: previousAcceptedWitness(repo), the newest
// `Witness: make verify green at` commit strictly before HEAD. A human
// copying a SHA into JSON to match a number the tool computes is a keystroke
// tax with a red attached — three reds in THE-NINE-MINORS, a fourth in
// THE-SLOW-RITUAL, every one of them "the manifest names the wrong witness".
//
// So the base is now DERIVED, by the same binary, through the same function
// the gate checks with. There is no second implementation to drift.
//
// DERIVING MUST NOT BECOME ASSERTING. Three things keep this a convenience
// and not a bypass:
//
//   1. The write is reachable ONLY through the explicit -rebase flag. The
//      gate path (run()) never writes; `make verify` never passes the flag.
//   2. What is written is re-measured and re-CHECKED at verify time. Deriving
//      the base at 10:00 proves nothing at 10:05: if a witness lands in
//      between, the measured base moves and the gate refuses the manifest it
//      just helped write. The check is unchanged.
//   3. ONLY base_commit is written. Declared changes — the rule ids, the
//      classes, the sentence digests and the human REASONS — are preserved
//      exactly. An invalid manifest is REFUSED, never repaired, so this can
//      never launder a manifest that would have failed ParseManifest.
//
// Rule LEDGER-REBASE-DERIVES-BASE-1 binds to rebase_test.go.

import (
	"encoding/json"
	"fmt"
)

// RebaseManifest returns the manifest bytes with base_commit set to base and
// everything else preserved. It refuses a manifest that does not already
// parse: repairing an invalid manifest is exactly the laundering this tool
// must not do.
func RebaseManifest(raw []byte, base string) ([]byte, error) {
	if !fullSHARe.MatchString(base) {
		return nil, fmt.Errorf("rebase: %q is not a 40-hex commit SHA", base)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("rebase refuses to repair an invalid manifest: %w", err)
	}
	m.BaseCommit = base
	if m.Changes == nil {
		// An empty list stays `[]`, never `null`: the file's shape is stable
		// across a re-base that declares nothing.
		m.Changes = []Change{}
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("rebase: encode manifest: %w", err)
	}
	return append(out, '\n'), nil
}

// ConsumedDeclarations names the manifest's declarations the diff against
// the NEW base no longer shows — declarations the witness at that base
// absorbed. THE-SIX-SMALL-ONES (2026-09-16): after a witness a manifest's
// declarations are consumed, the re-base preserves them by design (point 3
// above), and the next verify found them as a red — "DECLARED but not in the
// diff" — with nothing in between to say so. The owner decided where the
// reminder lives: here, in the re-base output, the first step after a
// witness. This NAMES; it never removes. Matching is the gate's own key,
// (rule_id, change_class), so what is named here is exactly what Reconcile
// would refuse.
func ConsumedDeclarations(m *Manifest, d *DiffDoc) []Change {
	if m == nil || d == nil {
		return nil
	}
	type key struct{ rule, class string }
	inDiff := map[key]struct{}{}
	for _, r := range d.Rules {
		for _, c := range r.Changes {
			inDiff[key{r.RuleID, c}] = struct{}{}
		}
	}
	var consumed []Change
	for _, c := range m.Changes {
		if _, still := inDiff[key{c.RuleID, c.ChangeClass}]; !still {
			consumed = append(consumed, c)
		}
	}
	return consumed
}

// ConsumedLine is the one line printed per consumed declaration. It does not
// start with `check`: a re-base is not a gate.
func ConsumedLine(c Change, base string) string {
	return fmt.Sprintf("ledger-rebase: CONSUMED declaration %s %s — the ledger diff against the new base %s no longer shows it (the witness absorbed it); the next verify's ledger-diff-gate will REFUSE this manifest unless the declaration is removed by hand. Nothing was removed.",
		c.RuleID, c.ChangeClass, base)
}

// RebaseSummary is the one line -rebase prints. It deliberately does NOT
// start with `check OK:` — the gate-witness evidence pattern — because a
// re-base is not a gate and must never read like one in a record.
func RebaseSummary(oldBase, newBase string, declared int) string {
	if oldBase == newBase {
		return fmt.Sprintf("ledger-rebase: base_commit already %s (%d declared change(s) preserved)", newBase, declared)
	}
	return fmt.Sprintf("ledger-rebase: base_commit %s -> %s (%d declared change(s) preserved)", oldBase, newBase, declared)
}
