// Package main — toolchain-parity (THE-UNCOMPARED-TOOLCHAIN, 2026-09-04).
//
// WHY THIS EXISTS
// ---------------
// The workflow declares one version per tool and every install derives from
// it. `make tool-versions` prints what is installed HERE. Both were true, and
// neither compared to the other — so for weeks the ledger was checked by
// rulefloor v0.8.1 locally and v0.7.0 in CI, and nothing failed.
//
// Two more drifts were sitting in the same blind spot when this gate was
// written: local grype 0.118.0 against a CI pin of v0.117.0, and — worse —
// GATE_WITNESS_SHA256 still naming the PRE-instrumentation gate-witness.sh.
// That second one would have failed CI outright on `sha256sum -c`, two
// slices after the change that caused it, with every local gate green.
//
// WHAT IT COMPARES. Everything the workflow env declares, against what this
// machine actually has:
//
//	RULEFLOOR_VERSION      ↔ rulefloor version --json
//	STATICCHECK_VERSION    ↔ staticcheck --version
//	GRYPE_VERSION          ↔ grype --version
//	GOVULNCHECK_VERSION    ↔ govulncheck -version
//	go.mod `go` directive  ↔ go version
//	GATE_WITNESS_SHA256    ↔ sha256(scripts/gate-witness.sh)
//	RULEFLOOR_GATE_SHA256  ↔ sha256(scripts/rulefloor-install-gate.sh)
//
// The last two matter as much as the versions: CI verifies those files by
// digest, so a stale pin there means CI is checking a file this repository
// no longer contains.
//
// WHAT IT DELIBERATELY DOES NOT COMPARE. gograph is not installed in CI at
// all — ci-verify subtracts the gograph targets on purpose — so there is no
// CI pin to disagree with. Recording that absence here is the point: it is a
// decision, not an oversight, and if gograph ever enters CI this list is
// where it must appear.
//
// Rule CI-LOCAL-PARITY-1 binds to parity_test.go. (TOOLCHAIN-PARITY-1 is a
// different, older rule: the IMAGE builder's Go version against go.mod.)
package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Pin is one declared-versus-installed comparison.
type Pin struct {
	// Tool is the human name ("rulefloor", "gate-witness.sh").
	Tool string
	// Source is where the declaration lives ("workflow env RULEFLOOR_VERSION",
	// "go.mod go directive").
	Source string
	// Declared is the pinned value, Observed is what this machine has. Both
	// are already normalized when they reach Decide.
	Declared string
	Observed string
}

// Decide is the gate's judgement: every pin must agree, and a pin whose
// declaration or observation is MISSING is a failure too — an absent tool
// cannot be said to match.
func Decide(pins []Pin) (failures []Pin, summary string, ok bool) {
	if len(pins) == 0 {
		return nil, "check FAILED: toolchain-parity compared nothing — a gate with an empty list is a decoration", false
	}
	var agreed []string
	for _, p := range pins {
		switch {
		case strings.TrimSpace(p.Declared) == "", strings.TrimSpace(p.Observed) == "":
			failures = append(failures, p)
		case p.Declared != p.Observed:
			failures = append(failures, p)
		default:
			agreed = append(agreed, p.Tool+" "+p.Declared)
		}
	}
	sort.Slice(failures, func(i, j int) bool { return failures[i].Tool < failures[j].Tool })
	if len(failures) > 0 {
		var lines []string
		for _, f := range failures {
			lines = append(lines, fmt.Sprintf("%s: %s declares %s, this machine has %s",
				f.Tool, f.Source, orMissing(f.Declared), orMissing(f.Observed)))
		}
		return failures, fmt.Sprintf(
			"check FAILED: toolchain-parity %d of %d pins disagree — CI and this machine are not running the same toolchain: %s",
			len(failures), len(pins), strings.Join(lines, "; ")), false
	}
	sort.Strings(agreed)
	return nil, fmt.Sprintf("check OK: toolchain-parity %d pins agree (%s)",
		len(pins), strings.Join(agreed, ", ")), true
}

func orMissing(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(missing)"
	}
	return s
}

// ParseWorkflowEnv reads the `env:` keys of a GitHub workflow. It is
// deliberately literal: a two-space-indented KEY: VALUE under the top-level
// `env:` block, values optionally quoted. Anything it cannot find comes back
// absent, and an absent declaration fails the gate rather than passing it.
func ParseWorkflowEnv(raw []byte) map[string]string {
	out := map[string]string{}
	inEnv := false
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "env:" {
			inEnv = true
			continue
		}
		if inEnv {
			// The block ends at the next top-level key.
			if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				break
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			key, value, found := strings.Cut(trimmed, ":")
			if !found {
				continue
			}
			out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return out
}

var (
	// staticcheck prints `2026.2.1 (0.8.1)` — the pin names the second form.
	staticcheckRe = regexp.MustCompile(`\(([0-9]+\.[0-9]+\.[0-9]+)\)`)
	// govulncheck prints `Go: …` / `Scanner: govulncheck@v1.7.0` lines.
	govulncheckRe = regexp.MustCompile(`govulncheck@v?([0-9]+\.[0-9]+\.[0-9]+)`)
	// `grype 0.118.0` or a bare version.
	semverRe = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+]*)`)
	// rulefloor version --json
	rulefloorRe = regexp.MustCompile(`"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)"`)
	// go.mod: `go 1.27.1`; go version: `go version go1.27.1 darwin/arm64`.
	goVersionRe = regexp.MustCompile(`go ?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

// KindPin is the DECLARED side's kind. The two sides are shaped differently
// and must be normalized differently: a workflow pin is bare semver
// ("v0.9.0"), while a tool reports something decorated ("2026.2.1 (0.8.1)",
// `{"version":"v0.9.0"}`). Running an observed-side normalizer over a pin
// finds nothing and reports "(missing)" — a false mismatch that says the
// declaration is absent when it is right there. Caught by running this gate
// against the real workflow before trusting it.
const KindPin = "pin"

// Normalize reduces a version string to bare semver so a `v` prefix or a
// tool's decorations cannot read as a mismatch. An unrecognisable string
// normalizes to "", which fails the gate — silence is never agreement.
func Normalize(kind, s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var re *regexp.Regexp
	switch kind {
	case "staticcheck":
		re = staticcheckRe
	case "govulncheck":
		re = govulncheckRe
	case "rulefloor":
		re = rulefloorRe
	case "go":
		re = goVersionRe
	case "sha256":
		// A digest is compared verbatim, lowercased.
		return strings.ToLower(s)
	default:
		re = semverRe
	}
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
