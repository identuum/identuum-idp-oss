// Package main — grype-gate (THE-STALE-DEPENDENCY, 2026-09-03).
//
// WHY THIS EXISTS
// ---------------
// `grype dir:. --fail-on high` exits 0 on a finding whose severity the
// database does not rate. That is not hypothetical: golang.org/x/crypto
// v0.55.0 carried GO-2026-6354 and GO-2026-6355 — both with a published fix
// in v0.56.0 — and both were reported as severity "Unknown", so the gate
// passed and the finding rode in three consecutive slice reports without
// anything failing.
//
// THE RULE THIS ENCODES (owner ruling, P-042): a finding WITH AN AVAILABLE
// FIX must fail. Not because it is severe — because somebody published the
// remedy and this repository has not taken it. A finding with NO fix cannot
// be actioned by a version bump, so it does not fail the gate; it is
// reported, and the currency rule decides what to do about it. The severity
// floor is kept as it was: High and Critical fail whether or not a fix
// exists, so this gate is strictly stronger than the flag it replaces.
//
// The only way past a fixable finding is an ALLOWLIST ENTRY NAMING IT, with
// a written reason. An entry without a reason is not an entry — the file
// cannot become a silent bypass by someone appending an id.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// GrypeDoc is the subset of grype's JSON this gate reads.
type GrypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fix      struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

// Allowlist is the committed file that lets a NAMED finding pass.
type Allowlist struct {
	SchemaVersion string           `json:"schema_version"`
	Entries       []AllowlistEntry `json:"entries"`
}

// AllowlistEntry names one advisory and says why it is tolerated. Reason and
// Ruling are both required: the first says what was decided, the second says
// who decided it and when, so the file records an owner ruling rather than a
// developer's convenience.
type AllowlistEntry struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Ruling  string `json:"ruling"`
	Added   string `json:"added"`
	Package string `json:"package,omitempty"`
}

// Finding is one judged match.
type Finding struct {
	ID          string
	Package     string
	Version     string
	Severity    string
	FixedIn     string
	Fixable     bool
	Allowlisted bool
}

// Decide judges a scan. It returns the findings that FAIL, a one-line
// summary for the gate-witness record, and whether the gate passes.
//
// A malformed allowlist entry (an id with no reason, or no ruling) is itself
// a failure: the file must not be able to excuse a finding by accident.
func Decide(doc GrypeDoc, allow Allowlist) (failures []Finding, summary string, ok bool) {
	byID := map[string]AllowlistEntry{}
	var badEntries []string
	for _, e := range allow.Entries {
		id := strings.TrimSpace(e.ID)
		if id == "" {
			badEntries = append(badEntries, "(entry with no id)")
			continue
		}
		if strings.TrimSpace(e.Reason) == "" || strings.TrimSpace(e.Ruling) == "" {
			badEntries = append(badEntries, id+" (no reason or no ruling)")
			continue
		}
		byID[id] = e
	}

	var fixable, unfixable, allowlisted, severe int
	for _, m := range doc.Matches {
		v := m.Vulnerability
		f := Finding{
			ID:       v.ID,
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			Severity: v.Severity,
			FixedIn:  strings.Join(v.Fix.Versions, ","),
		}
		f.Fixable = v.Fix.State == "fixed" && len(v.Fix.Versions) > 0
		_, f.Allowlisted = byID[v.ID]

		isSevere := strings.EqualFold(v.Severity, "high") || strings.EqualFold(v.Severity, "critical")
		if isSevere {
			severe++
		}
		switch {
		case f.Fixable && f.Allowlisted:
			allowlisted++
			// An allowlist covers the "you have not taken the fix" verdict,
			// never a High/Critical: severity still fails.
			if isSevere {
				failures = append(failures, f)
			}
		case f.Fixable:
			fixable++
			failures = append(failures, f)
		default:
			unfixable++
			if isSevere {
				failures = append(failures, f)
			}
		}
	}

	sort.Slice(failures, func(i, j int) bool { return failures[i].ID < failures[j].ID })

	if len(badEntries) > 0 {
		sort.Strings(badEntries)
		return failures, fmt.Sprintf(
			"check FAILED: grype-gate allowlist is malformed: %s — an entry without a reason and a ruling is not an allowlist entry",
			strings.Join(badEntries, ", ")), false
	}
	if len(failures) > 0 {
		var names []string
		for _, f := range failures {
			names = append(names, fmt.Sprintf("%s (%s %s, fixed in %s)", f.ID, f.Package, f.Version, orDash(f.FixedIn)))
		}
		return failures, fmt.Sprintf(
			"check FAILED: grype-gate matches=%d fixable=%d severe=%d — take the fix or allowlist it by name with a reason: %s",
			len(doc.Matches), fixable, severe, strings.Join(names, "; ")), false
	}
	return nil, fmt.Sprintf(
		"check OK: grype-gate matches=%d fixable=0 allowlisted=%d unfixable=%d severe=0",
		len(doc.Matches), allowlisted, unfixable), true
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ParseDoc and ParseAllowlist keep the I/O boundary thin so the decision
// above stays testable without a scanner or a file.
func ParseDoc(raw []byte) (GrypeDoc, error) {
	var d GrypeDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, fmt.Errorf("grype output: invalid JSON: %w", err)
	}
	return d, nil
}

func ParseAllowlist(raw []byte) (Allowlist, error) {
	var a Allowlist
	if len(strings.TrimSpace(string(raw))) == 0 {
		return a, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("allowlist: invalid JSON: %w", err)
	}
	return a, nil
}
