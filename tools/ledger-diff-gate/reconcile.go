// Package main — ledger-diff-gate (THE-LEDGER-DIFF-GATE, 2026-09-02).
//
// A ledger sentence never changes silently again. `make verify` runs
// `rulefloor ledger-diff --base <previous accepted witness> --json` and
// reconciles the classified ledger changes BOTH ways against a committed,
// single-use, SHA-scoped amendment manifest (ledger-amendments.v1):
//
//   - a change in the diff that the manifest does not declare  → FAIL
//   - a declaration in the manifest that the diff does not show → FAIL
//   - a sentence_changed row whose after_sentence_sha256 differs → FAIL
//   - manifest base_commit ≠ the previous accepted witness       → FAIL
//   - rulefloor exit 2 / status cannot_evaluate / bad JSON /
//     truncated / exit-status disagreement                        → FAIL
//   - exit 0 (same) with an empty manifest, or exit 1 (different)
//     fully reconciled                                            → pass
//
// The pass line is `check OK: ledger-diff reconciled …` so the vendored
// gate-witness (EVIDENCE_RE `^check OK:`) records it — with the base SHA and
// the sha256 of the ledger-diff.v1 document — in GATE-RUN.txt.
//
// "Previous accepted witness" is measured from git history, not remembered:
// the most recent commit reachable from HEAD~1 whose subject is
// `Witness: make verify green at <sha>` — the record-only commit the close
// ritual makes after a green verify. Because every witness moves the base,
// a manifest can serve exactly one verify→witness cycle: reusing it fails on
// base_commit.
//
// This file is the pure reconciliation logic (unit-tested; rule
// LEDGER-DIFF-RECONCILED-1 binds to its test). main.go does the I/O.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ManifestSchema is the only accepted manifest schema version.
const ManifestSchema = "ledger-amendments.v1"

// DiffSchema is the only accepted rulefloor ledger-diff schema version.
const DiffSchema = "rulefloor.ledger-diff.v1"

// ClassSentenceChanged is the one change class that carries a digest.
const ClassSentenceChanged = "sentence_changed"

var fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Manifest is ledger-amendments.v1.
type Manifest struct {
	SchemaVersion string   `json:"schema_version"`
	BaseCommit    string   `json:"base_commit"`
	Changes       []Change `json:"changes"`
}

// Change is one declared ledger change.
type Change struct {
	RuleID              string `json:"rule_id"`
	ChangeClass         string `json:"change_class"`
	AfterSentenceSHA256 string `json:"after_sentence_sha256,omitempty"`
	Reason              string `json:"reason"`
}

// DiffDoc is the subset of rulefloor.ledger-diff.v1 the gate reads.
type DiffDoc struct {
	SchemaVersion    string     `json:"schema_version"`
	Status           string     `json:"status"`
	BaseRef          string     `json:"base_ref"`
	BaseCommit       string     `json:"base_commit"`
	HeadersChanged   bool       `json:"headers_changed"`
	HeaderChanges    []string   `json:"header_changes"`
	Rules            []DiffRule `json:"rules"`
	TotalRuleChanges int        `json:"total_rule_changes"`
	Truncated        bool       `json:"truncated"`
	Error            string     `json:"error,omitempty"`
}

// DiffRule is one rule's classified changes. The sentence digests are the
// canonical-sentence sha256 values rulefloor emits for sentence_changed rows.
type DiffRule struct {
	RuleID               string   `json:"rule_id"`
	Changes              []string `json:"changes"`
	BeforeSentenceSHA256 string   `json:"before_sentence_sha256,omitempty"`
	AfterSentenceSHA256  string   `json:"after_sentence_sha256,omitempty"`
}

// Outcome is the reconciled result, rendered as the evidence line.
type Outcome struct {
	BaseCommit    string
	Status        string
	RuleChanges   int
	Classes       []string
	HeaderChanges []string
	DiffSHA256    string
}

// EvidenceLine is the single summary line gate-witness records.
func (o Outcome) EvidenceLine() string {
	classes := "none"
	if len(o.Classes) > 0 {
		classes = strings.Join(o.Classes, ",")
	}
	headers := "none"
	if len(o.HeaderChanges) > 0 {
		headers = strings.Join(o.HeaderChanges, ",")
	}
	return fmt.Sprintf("check OK: ledger-diff reconciled base=%s status=%s rule_changes=%d classes=%s header_changes=%s ledger_diff_sha256=%s",
		o.BaseCommit, o.Status, o.RuleChanges, classes, headers, o.DiffSHA256)
}

// ParseManifest validates ledger-amendments.v1 structurally.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: invalid JSON: %w", err)
	}
	if m.SchemaVersion != ManifestSchema {
		return nil, fmt.Errorf("manifest: schema_version %q, want %q", m.SchemaVersion, ManifestSchema)
	}
	if !fullSHARe.MatchString(m.BaseCommit) {
		return nil, errors.New("manifest: base_commit must be the full 40-hex commit SHA of the previous accepted witness")
	}
	seen := map[string]struct{}{}
	for i, c := range m.Changes {
		if strings.TrimSpace(c.RuleID) == "" || strings.TrimSpace(c.ChangeClass) == "" {
			return nil, fmt.Errorf("manifest: changes[%d] needs rule_id and change_class", i)
		}
		if strings.TrimSpace(c.Reason) == "" {
			return nil, fmt.Errorf("manifest: changes[%d] (%s %s) needs a reason", i, c.RuleID, c.ChangeClass)
		}
		key := c.RuleID + "|" + c.ChangeClass
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("manifest: duplicate declaration %s %s", c.RuleID, c.ChangeClass)
		}
		seen[key] = struct{}{}
		if c.ChangeClass == ClassSentenceChanged {
			if !sha256Re.MatchString(c.AfterSentenceSHA256) {
				return nil, fmt.Errorf("manifest: %s sentence_changed requires after_sentence_sha256 (64 hex)", c.RuleID)
			}
		} else if c.AfterSentenceSHA256 != "" {
			return nil, fmt.Errorf("manifest: %s %s must not carry after_sentence_sha256", c.RuleID, c.ChangeClass)
		}
	}
	return &m, nil
}

// ParseDiff validates the rulefloor document structurally.
func ParseDiff(raw []byte) (*DiffDoc, error) {
	var d DiffDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("ledger-diff: invalid JSON: %w", err)
	}
	if d.SchemaVersion != DiffSchema {
		return nil, fmt.Errorf("ledger-diff: schema_version %q, want %q", d.SchemaVersion, DiffSchema)
	}
	return &d, nil
}

// Reconcile is the gate's decision. exitCode is rulefloor's process exit
// (0 same, 1 different, 2 cannot evaluate); expectedBase is the previous
// accepted witness measured from git; diffSHA256 is the hex digest of the
// raw document (recorded, not checked).
func Reconcile(m *Manifest, rawDiff []byte, exitCode int, expectedBase string, diffSHA256 string) (*Outcome, error) {
	if m == nil {
		return nil, errors.New("manifest: missing")
	}
	if !fullSHARe.MatchString(expectedBase) {
		return nil, errors.New("previous accepted witness: not found in history (no `Witness: make verify green at` commit before HEAD)")
	}
	if m.BaseCommit != expectedBase {
		return nil, fmt.Errorf("manifest base_commit %s is not the previous accepted witness %s (a manifest serves one verify→witness cycle)", m.BaseCommit, expectedBase)
	}
	if exitCode == 2 {
		return nil, fmt.Errorf("ledger-diff: exit 2 (cannot evaluate): %s", strings.TrimSpace(firstLine(rawDiff)))
	}
	if exitCode != 0 && exitCode != 1 {
		return nil, fmt.Errorf("ledger-diff: unexpected exit %d", exitCode)
	}
	d, err := ParseDiff(rawDiff)
	if err != nil {
		return nil, err
	}
	if d.Truncated {
		return nil, errors.New("ledger-diff: document truncated — cannot reconcile a partial diff")
	}
	switch d.Status {
	case "same":
		if exitCode != 0 {
			return nil, fmt.Errorf("ledger-diff: status same but exit %d", exitCode)
		}
	case "different":
		if exitCode != 1 {
			return nil, fmt.Errorf("ledger-diff: status different but exit %d", exitCode)
		}
	default:
		return nil, fmt.Errorf("ledger-diff: status %q (error: %s) — cannot reconcile", d.Status, d.Error)
	}
	if d.BaseCommit != "" && d.BaseCommit != expectedBase {
		return nil, fmt.Errorf("ledger-diff: base_commit %s ≠ expected %s", d.BaseCommit, expectedBase)
	}

	// Diff side: (rule_id, class) → after digest (sentence_changed only).
	type key struct{ rule, class string }
	inDiff := map[key]string{}
	classSet := map[string]struct{}{}
	for _, r := range d.Rules {
		for _, c := range r.Changes {
			k := key{r.RuleID, c}
			if _, dup := inDiff[k]; dup {
				return nil, fmt.Errorf("ledger-diff: duplicate row %s %s", r.RuleID, c)
			}
			digest := ""
			if c == ClassSentenceChanged {
				if !sha256Re.MatchString(r.AfterSentenceSHA256) {
					return nil, fmt.Errorf("ledger-diff: %s sentence_changed row lacks after_sentence_sha256 — cannot reconcile the digest", r.RuleID)
				}
				digest = r.AfterSentenceSHA256
			}
			inDiff[k] = digest
			classSet[c] = struct{}{}
		}
	}
	// Manifest side.
	declared := map[key]Change{}
	for _, c := range m.Changes {
		declared[key{c.RuleID, c.ChangeClass}] = c
	}
	// Both directions.
	var problems []string
	for k, digest := range inDiff {
		c, ok := declared[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("UNDECLARED ledger change: %s %s", k.rule, k.class))
			continue
		}
		if k.class == ClassSentenceChanged && c.AfterSentenceSHA256 != digest {
			problems = append(problems, fmt.Sprintf("DIGEST MISMATCH: %s sentence_changed declared %s, ledger has %s", k.rule, c.AfterSentenceSHA256, digest))
		}
	}
	for k := range declared {
		if _, ok := inDiff[k]; !ok {
			problems = append(problems, fmt.Sprintf("DECLARED but not in the diff: %s %s", k.rule, k.class))
		}
	}
	if len(inDiff) == 0 && d.HeadersChanged {
		problems = append(problems, fmt.Sprintf("ledger headers changed (%s) with no rule change to explain them", strings.Join(d.HeaderChanges, ",")))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, errors.New("ledger-diff NOT reconciled:\n  " + strings.Join(problems, "\n  "))
	}
	classes := make([]string, 0, len(classSet))
	for c := range classSet {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	return &Outcome{
		BaseCommit:    expectedBase,
		Status:        d.Status,
		RuleChanges:   len(inDiff),
		Classes:       classes,
		HeaderChanges: append([]string(nil), d.HeaderChanges...),
		DiffSHA256:    diffSHA256,
	}, nil
}

func firstLine(b []byte) string {
	first, _, _ := strings.Cut(string(b), "\n")
	return first
}
