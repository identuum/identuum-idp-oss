package main

// reconcile_test.go — RULE: LEDGER-DIFF-RECONCILED-1. Every failure mode the
// gate promises, and the two passes, against fixtures shaped like
// rulefloor.ledger-diff.v1 (measured 2026-09-02: status same/different/
// cannot_evaluate, exit 0/1/2, rules[].changes[], truncated).

import (
	"strings"
	"testing"
)

const base = "2359736c3bcd14e19f8a03d458fa49e8256d5080"
const otherBase = "27a808ffc1be819c5b7653f24e13d4486effe595"
const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func manifest(t *testing.T, changes string) *Manifest {
	t.Helper()
	m, err := ParseManifest([]byte(`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[` + changes + `]}`))
	if err != nil {
		t.Fatalf("fixture manifest: %v", err)
	}
	return m
}

func sameDoc() []byte {
	return []byte(`{"schema_version":"rulefloor.ledger-diff.v1","command":"ledger-diff","status":"same","base_ref":"` + base + `","base_commit":"` + base + `","before":{"floor":207,"red_proofs":207},"after":{"floor":207,"red_proofs":207},"headers_changed":false,"header_changes":[],"rules":[],"total_rule_changes":0,"truncated":false}`)
}

func differentDoc(rules string, truncated bool) []byte {
	tr := "false"
	if truncated {
		tr = "true"
	}
	return []byte(`{"schema_version":"rulefloor.ledger-diff.v1","command":"ledger-diff","status":"different","base_ref":"` + base + `","base_commit":"` + base + `","before":{"floor":206,"red_proofs":206},"after":{"floor":207,"red_proofs":207},"headers_changed":true,"header_changes":["floor_changed","red_proofs_changed"],"rules":[` + rules + `],"total_rule_changes":2,"truncated":` + tr + `}`)
}

const addedRow = `{"rule_id":"NEW-1","changes":["rule_added"],"after_sentence_excerpt":"…"}`
const sentenceRow = `{"rule_id":"OLD-1","changes":["sentence_changed"],"before_sentence_sha256":"` + shaB + `","after_sentence_sha256":"` + shaA + `"}`
const fingerprintRow = `{"rule_id":"OLD-2","changes":["test_fingerprint_changed"]}`

const declAdded = `{"rule_id":"NEW-1","change_class":"rule_added","reason":"new rule"}`
const declSentence = `{"rule_id":"OLD-1","change_class":"sentence_changed","after_sentence_sha256":"` + shaA + `","reason":"sharper wording"}`
const declSentenceWrong = `{"rule_id":"OLD-1","change_class":"sentence_changed","after_sentence_sha256":"` + shaB + `","reason":"sharper wording"}`
const declFingerprint = `{"rule_id":"OLD-2","change_class":"test_fingerprint_changed","reason":"check body edited"}`

func wantFail(t *testing.T, err error, needle string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected FAIL containing %q, got pass", needle)
	}
	if !strings.Contains(err.Error(), needle) {
		t.Fatalf("FAIL reason %q does not name %q", err.Error(), needle)
	}
}

// RULE: LEDGER-DIFF-RECONCILED-1
func TestRuleLedgerDiffReconciled1_UndeclaredFails_WrongDigestFails_ReconciledPasses(t *testing.T) {
	full := differentDoc(addedRow+","+sentenceRow+","+fingerprintRow, false)

	t.Run("change not declared → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, declAdded+","+declSentence), full, 1, base, "d")
		wantFail(t, err, "UNDECLARED ledger change: OLD-2 test_fingerprint_changed")
	})
	t.Run("declaration not in the diff → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, declAdded), sameDoc(), 0, base, "d")
		wantFail(t, err, "DECLARED but not in the diff: NEW-1 rule_added")
	})
	t.Run("sentence digest mismatch → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, declAdded+","+declSentenceWrong+","+declFingerprint), full, 1, base, "d")
		wantFail(t, err, "DIGEST MISMATCH: OLD-1")
	})
	t.Run("wrong base_commit → FAIL (a manifest is single-use)", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), sameDoc(), 0, otherBase, "d")
		wantFail(t, err, "is not the previous accepted witness")
	})
	// THE-UNEARNED-WITNESS asked whether base_commit earns its place, since
	// its only use is equality with a value the gate already derives from
	// git. THIS IS THE CASE THAT ANSWERS IT — and the answer is yes.
	//
	// `test_fingerprint_changed` carries NO DIGEST. ParseManifest refuses one
	// (only sentence_changed may carry after_sentence_sha256), and the diff
	// row for a fingerprint change carries none either. So a declaration of
	// (rule, test_fingerprint_changed) is CONTENT-FREE: it reconciles the
	// edit it was written for and every later, different edit to the same
	// rule's test, with a reason describing only the first.
	//
	// Two-way reconciliation cannot see the difference — both cycles produce
	// the same row and the same declaration. base_commit is the only thing
	// that does, because a witness landed in between. Remove it and a stale
	// manifest launders the next fingerprint change silently.
	t.Run("base_commit EARNS ITS PLACE: content alone cannot tell two fingerprint cycles apart", func(t *testing.T) {
		doc := differentDoc(fingerprintRow, false)

		// Cycle 1 — the edit the reason was written for.
		if _, err := Reconcile(manifest(t, declFingerprint), doc, 1, base, "d"); err != nil {
			t.Fatalf("the declaring cycle must pass: %v", err)
		}
		// Cycle 2 — a DIFFERENT edit to the same rule's test. The document
		// reconciliation reads is identical in every field it inspects, so
		// the same stale declaration reconciles it just as happily.
		if _, err := Reconcile(manifest(t, declFingerprint), doc, 1, base, "d"); err != nil {
			t.Fatalf("content-based reconciliation cannot distinguish the second edit: %v", err)
		}
		// …and base_commit is what refuses it, once a witness has landed.
		_, err := Reconcile(manifest(t, declFingerprint), doc, 1, otherBase, "d")
		wantFail(t, err, "is not the previous accepted witness")

		// The premise above, pinned: this class may not carry a digest, so
		// there is nothing else for reconciliation to compare.
		withDigest := `{"rule_id":"OLD-2","change_class":"test_fingerprint_changed","after_sentence_sha256":"` + shaA + `","reason":"r"}`
		if _, err := ParseManifest([]byte(`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[` + withDigest + `]}`)); err == nil {
			t.Fatal("test_fingerprint_changed accepted a digest — if it ever carries one, re-open the base_commit question")
		}
	})

	t.Run("no previous witness in history → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), sameDoc(), 0, "", "d")
		wantFail(t, err, "previous accepted witness: not found")
	})
	t.Run("rulefloor exit 2 → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), []byte(`{"schema_version":"rulefloor.ledger-diff.v1","status":"cannot_evaluate","error":"resolve Git base"}`), 2, base, "d")
		wantFail(t, err, "exit 2")
	})
	t.Run("status cannot_evaluate with exit 0 → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), []byte(`{"schema_version":"rulefloor.ledger-diff.v1","status":"cannot_evaluate","rules":[],"truncated":false}`), 0, base, "d")
		wantFail(t, err, `status "cannot_evaluate"`)
	})
	t.Run("bad JSON → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), []byte(`{"schema_version":`), 0, base, "d")
		wantFail(t, err, "invalid JSON")
	})
	t.Run("wrong schema → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), []byte(`{"schema_version":"rulefloor.ledger-diff.v0","status":"same","rules":[]}`), 0, base, "d")
		wantFail(t, err, "schema_version")
	})
	t.Run("truncated → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, declAdded+","+declSentence+","+declFingerprint), differentDoc(addedRow+","+sentenceRow+","+fingerprintRow, true), 1, base, "d")
		wantFail(t, err, "truncated")
	})
	t.Run("exit/status disagreement → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), sameDoc(), 1, base, "d")
		wantFail(t, err, "status same but exit 1")
	})
	t.Run("sentence_changed row without a digest → FAIL closed", func(t *testing.T) {
		_, err := Reconcile(manifest(t, declSentence), differentDoc(`{"rule_id":"OLD-1","changes":["sentence_changed"]}`, false), 1, base, "d")
		wantFail(t, err, "lacks after_sentence_sha256")
	})
	t.Run("headers changed with no rule change → FAIL", func(t *testing.T) {
		_, err := Reconcile(manifest(t, ""), differentDoc("", false), 1, base, "d")
		wantFail(t, err, "headers changed")
	})
	t.Run("exit 0 same + empty manifest → pass", func(t *testing.T) {
		out, err := Reconcile(manifest(t, ""), sameDoc(), 0, base, "deadbeef")
		if err != nil {
			t.Fatalf("pass expected: %v", err)
		}
		if out.Status != "same" || out.RuleChanges != 0 || !strings.HasPrefix(out.EvidenceLine(), "check OK: ledger-diff reconciled base="+base+" status=same rule_changes=0") {
			t.Fatalf("outcome = %+v / %q", out, out.EvidenceLine())
		}
	})
	t.Run("exit 1 fully reconciled (every class incl. the digest) → pass", func(t *testing.T) {
		out, err := Reconcile(manifest(t, declAdded+","+declSentence+","+declFingerprint), full, 1, base, "deadbeef")
		if err != nil {
			t.Fatalf("pass expected: %v", err)
		}
		line := out.EvidenceLine()
		for _, want := range []string{"status=different", "rule_changes=3", "classes=rule_added,sentence_changed,test_fingerprint_changed", "header_changes=floor_changed,red_proofs_changed", "ledger_diff_sha256=deadbeef"} {
			if !strings.Contains(line, want) {
				t.Fatalf("evidence line %q lacks %q", line, want)
			}
		}
	})
}

func TestParseManifest_Shape(t *testing.T) {
	bad := []string{
		`{"schema_version":"ledger-amendments.v0","base_commit":"` + base + `","changes":[]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"2359736","changes":[]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[{"rule_id":"X","change_class":"rule_added"}]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[{"rule_id":"X","change_class":"sentence_changed","reason":"r"}]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[{"rule_id":"X","change_class":"rule_added","after_sentence_sha256":"` + shaA + `","reason":"r"}]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[` + declAdded + `,` + declAdded + `]}`,
		`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[],"extra":1}`,
	}
	for i, b := range bad {
		if _, err := ParseManifest([]byte(b)); err == nil {
			t.Errorf("bad[%d] must be refused: %s", i, b)
		}
	}
	if _, err := ParseManifest([]byte(`{"schema_version":"ledger-amendments.v1","base_commit":"` + base + `","changes":[` + declSentence + `]}`)); err != nil {
		t.Errorf("valid manifest refused: %v", err)
	}
}
