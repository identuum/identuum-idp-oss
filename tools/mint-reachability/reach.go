// Package main — mint-reachability (THE-UNMINTED-DIFF, 2026-09-04).
//
// OWNER RULING: a slice whose diff cannot reach the running appliance does
// not pay the e2e mint. This decides that, and it is COMPUTED, never judged.
//
// THE DIRECTION OF THE DEFAULT IS THE WHOLE DESIGN. A path is only
// no-reach when it MATCHES A DECLARED ENTRY. Everything else requires the
// mint — go.mod and go.sum included, and an unrecognised path most of all.
// A classifier that guesses "probably harmless" for something it has never
// seen is how a real change ships unminted, so the unknown path is the one
// case this is most careful about: it fails closed, loudly, naming the file.
//
// WHAT MAY BE DECLARED NO-REACH, and why each cannot touch the appliance:
//
//	.github/**            CI configuration. Read by GitHub, never by the
//	                      binary, never served.
//	docs/**, *.md         Prose. Nothing compiles or serves it.
//	RULE-FLOOR.md         The ledger table (a .md, listed for the record).
//	ledger-amendments.json  The amendment manifest: read by ledger-diff-gate
//	                      at verify time, never by the appliance.
//	GATE-RUN*.txt         Gate records. Written BY the gates, read by
//	                      gate-witness check. Not compiled, not served.
//	                      (Added to the seed: a witness commit touches only
//	                      this, so without it every post-mint witness would
//	                      force the next mint — see P-052.)
//	wiki/**               A sibling repository's prose.
//	*_test.go             Excluded from every non-test build by the Go
//	                      toolchain itself, so no test file is in the binary
//	                      the appliance runs. This is a property of `go
//	                      build`, not a convention, which is why it can be
//	                      declared without an import analysis: a *_test.go
//	                      file cannot be imported by a non-test file at all.
//
// Everything else — internal/**, cmd/**, auth/**, deployment/**, the
// Makefile, the e2e specs and harness, go.mod, go.sum — REQUIRES the mint.
//
// Rule MINT-REACHABILITY-1 binds to reach_test.go.
package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// NoReachEntry is one declared pattern plus the reason it cannot reach the
// appliance. The reason is not decoration: an entry nobody can justify is an
// entry that should not exist, and the evidence line prints them.
type NoReachEntry struct {
	Pattern string
	Why     string
}

// NoReachSet is the committed declaration. Order does not matter; a path is
// no-reach if ANY entry matches it.
var NoReachSet = []NoReachEntry{
	{".github/**", "CI configuration: read by GitHub, never compiled, never served"},
	{"docs/**", "prose"},
	{"**/*.md", "prose (covers RULE-FLOOR.md and every README)"},
	{"ledger-amendments.json", "the amendment manifest, read by ledger-diff-gate at verify time"},
	{"GATE-RUN*.txt", "gate records: written by the gates, read by gate-witness check"},
	{"MINT-STATE.json", "this classifier's own marker: written BY the mint, read only here. It is GITIGNORED — committing it created a loop, because the mint writes it on completion and that commit moved the tree the e2e record had just pinned, so every mint invalidated itself. Kept in the set anyway: an entry costs nothing and a future checkout that tracks it is then covered"},
	{"wiki/**", "a sibling repository's prose"},
	{"**/*_test.go", "the Go toolchain excludes *_test.go from every non-test build"},
}

// Decision is what the harness acts on.
type Decision struct {
	// Required is the answer. Changed is every path considered.
	Required bool
	Changed  []string
	// NoReach are the paths a declared entry covered, with the entry that
	// covered each; Reaching are the paths that force the mint.
	NoReach  map[string]string
	Reaching []string
	// Unknown paths are reaching too, listed separately because "I have
	// never seen this" is a different statement from "this reaches".
	Unknown []string
}

// Decide classifies a change set. An EMPTY change set is skippable: there is
// nothing to reach the appliance with. A path that matches nothing is
// reaching AND unknown.
func Decide(changed []string, set []NoReachEntry) Decision {
	d := Decision{Changed: append([]string(nil), changed...), NoReach: map[string]string{}}
	sort.Strings(d.Changed)
	for _, p := range d.Changed {
		matched := ""
		for _, e := range set {
			if matchPath(e.Pattern, p) {
				matched = e.Pattern
				break
			}
		}
		if matched != "" {
			d.NoReach[p] = matched
			continue
		}
		d.Reaching = append(d.Reaching, p)
		d.Unknown = append(d.Unknown, p)
	}
	d.Required = len(d.Reaching) > 0
	return d
}

// matchPath supports exactly two shapes, because a pattern language nobody
// can predict is a pattern language that will be widened by accident:
//
//	prefix/**   — that directory and everything under it
//	**/*.ext    — any file with that suffix, at any depth
//
// Anything else is matched literally, or by path.Match within one segment
// (so GATE-RUN*.txt works at the repository root).
func matchPath(pattern, p string) bool {
	p = strings.TrimPrefix(path.Clean(p), "./")
	// A CATCH-ALL IS NOT A DECLARATION. `**`, `**/*` and `*` name nothing in
	// particular, so they cannot state why anything is unreachable — and an
	// entry widened to one of them would silently skip the mint for every
	// change on earth. They match NOTHING here, which makes that widening
	// fail closed by construction instead of by review. Caught by this
	// tool's own test before it ever ran (THE-UNMINTED-DIFF).
	if isCatchAll(pattern) {
		return false
	}
	switch {
	case strings.HasSuffix(pattern, "/**"):
		dir := strings.TrimSuffix(pattern, "/**")
		if dir == "" || isCatchAll(dir) {
			return false
		}
		return p == dir || strings.HasPrefix(p, dir+"/")
	case strings.HasPrefix(pattern, "**/"):
		suffix := strings.TrimPrefix(pattern, "**/")
		if rest, found := strings.CutPrefix(suffix, "*"); found {
			// `**/*` with nothing after the star matches every path; refuse.
			if rest == "" {
				return false
			}
			return strings.HasSuffix(p, rest)
		}
		return path.Base(p) == suffix
	default:
		if ok, err := path.Match(pattern, p); err == nil && ok {
			return true
		}
		return pattern == p
	}
}

// isCatchAll names the patterns that would cover every path. They are
// refused rather than honoured, so no-reach can only ever be stated about
// something specific.
func isCatchAll(pattern string) bool {
	switch strings.TrimSpace(pattern) {
	case "", "*", "**", "**/*", "**/**", "./**":
		return true
	}
	return false
}

// Line renders the one evidence line the harness records. The `check OK:`
// prefix is the gate-witness evidence pattern; this classifier does not fail
// a build, it decides one — so both answers are OK lines, and each states
// the decision explicitly rather than leaving it to be inferred.
func (d Decision) Line() string {
	if len(d.Changed) == 0 {
		return "check OK: mint-reachability SKIPPABLE — no change since the last minted witness"
	}
	if d.Required {
		return fmt.Sprintf(
			"check OK: mint-reachability MINT REQUIRED — %d of %d changed path(s) reach the appliance: %s",
			len(d.Reaching), len(d.Changed), strings.Join(clip(d.Reaching, 8), ", "))
	}
	var justified []string
	for _, p := range d.Changed {
		justified = append(justified, fmt.Sprintf("%s [%s]", p, d.NoReach[p]))
	}
	return fmt.Sprintf(
		"check OK: mint-reachability SKIPPABLE — all %d changed path(s) are declared no-reach: %s",
		len(d.Changed), strings.Join(justified, "; "))
}

func clip(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("…and %d more", len(s)-n))
}
