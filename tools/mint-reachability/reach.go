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
//	CI-WITNESS.txt        The committed CI claim: fetched by `make ci-fetch`
//	                      from a CI artifact, judged by tools/ci-witness at
//	                      verify time. Not compiled, not served. P-055
//	                      (2026-09-04) declined this entry because no mint had
//	                      ever been forced by a record ALONE; by 2026-09-07 two
//	                      wiki closes had been refused on ranges made ONLY of
//	                      CI-WITNESS.txt, GATE-RUN.txt and
//	                      ledger-amendments.json, so the number P-055 set to
//	                      beat was beaten and the entry added
//	                      (THE-RECORD-ONLY-CLOSE).
//	tools/<program>/**    A gate program: each directory in GateProgramDirs is
//	                      its own package main, run at verify time, and the
//	                      appliance never executes it — cmd/identuum-idp's
//	                      build closure (`go list -deps ./cmd/...`, what
//	                      deployment/Dockerfile.local compiles) contains no
//	                      tools/ package. That is not taken on trust: closure.go
//	                      re-proves it whenever a decision relies on one of
//	                      these entries and fails CLOSED if a declared program
//	                      is ever imported by the product, and closure_test.go
//	                      re-proves it on every test run. The root tools/tools.go
//	                      (package tools, a helper library) is NOT a gate
//	                      program and is NOT declared; only the listed programs
//	                      are (THE-TOOLS-THAT-CANNOT-REACH, 2026-09-13).
//
// THE SIBLING'S PATHS ARE NAMESPACED, NOT RELOCATED. main.go reports the ui's
// paths as identuum-ui/<path> so a line can never confuse the repositories.
// The prefix is stripped again before an entry is matched (SiblingPrefixes),
// because a record is a record in either repository: until 2026-09-07 the
// entries were matched against the prefixed path, so the root-anchored
// GATE-RUN*.txt and the literal ledger-amendments.json never matched a ui
// record and every record-only ui commit read as REACHING.
//
//	scripts/**            The gate scripts (gate-witness.sh, ci-record.sh,
//	                      verify-check.sh and their tests). THIS REPOSITORY
//	                      ONLY, and proved rather than trusted: the image
//	                      recipe never copies a scripts/ path into the
//	                      runtime stage and never runs one, and no package
//	                      embeds one (`go list -f {{.EmbedPatterns}}` names
//	                      only migrations/*.sql) — re-measured by
//	                      reach_test.go on every run (THE-SIX-SMALL-ONES,
//	                      2026-09-16).
//
//	.legattus-policy.json THIS REPOSITORY ONLY: Legattus v0.1.4's one in-tree
//	                      file, the committed policy, read by Legattus and by
//	                      nothing the appliance builds or serves — proved the
//	                      way scripts/** is (runtime stage copies only --from=
//	                      artifacts; no embed pattern names it), re-measured
//	                      by reach_test.go (THE-LEGATTUS-THAT-LEAVES-THE-TREE-
//	                      ALONE, 2026-09-16).
//	identuum-ui/Makefile  THE SIBLING'S Makefile ONLY (SiblingOnly): its
//	                      recipes never reach the ui image — the Dockerfile
//	                      RUNs npm/pnpm and never make, the runner stage
//	                      copies only --from= artifacts, package.json scripts
//	                      invoke no make — re-proved from the sibling's own
//	                      files at every reliant decision and by
//	                      reach_test.go (THE-EIGHT-QUICK-ONES, 2026-09-16).
//
// Everything else — internal/**, cmd/**, auth/**, deployment/**, THIS
// module's Makefile, the e2e specs and harness (e2e-full/scripts/ included),
// go.mod, go.sum, the root tools/tools.go — REQUIRES the mint.
//
// Rule MINT-REACHABILITY-1 binds to reach_test.go; rule TOOLS-NO-REACH-1
// binds the gate-program entries and their proof to closure_test.go.
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
	// ThisRepoOnly entries are matched only against this repository's own
	// paths, never against a sibling's namespaced ones: a proof about THIS
	// module's build closure says nothing about a sibling's tree.
	ThisRepoOnly bool
	// SiblingOnly entries are the mirror: matched only against a sibling's
	// namespaced paths, never this repository's own — a proof about the
	// sibling's image says nothing about this module (THE-EIGHT-QUICK-ONES,
	// 2026-09-16: the ui's Makefile is no-reach, this module's is not).
	SiblingOnly bool
}

// GateProgramDirs names the gate programs under tools/: each is its own
// package main, run at verify time by a Makefile target, and never built into
// the appliance. MEASURED on 2026-09-13 (THE-TOOLS-THAT-CANNOT-REACH): `go
// list -deps ./cmd/...` — the closure deployment/Dockerfile.local compiles —
// held 487 packages, 39 of this module, and NONE under tools/; no package in
// the module, test or non-test, imports any of them. The list is NAMES, not
// `tools/**`: tools/tools.go at the root is a library package (imported by
// nothing, and equally outside the closure) that is not a gate program and is
// not declared here. Adding a directory to this list is a declaration that
// closure.go will re-prove, so an entry that is ever imported by the product
// fails the decision rather than excusing it. THE-LAST-BORROWER (2026-09-21):
// "grype-gate" left this list with the program — tools/grype-gate was retired
// when this repository, its last consumer, switched to lictor (the port); the
// closure proof was re-run on the ten that remain.
var GateProgramDirs = []string{
	"api-docgen",
	"ci-witness",
	"clockfuse",
	"devseed",
	"integration-witness",
	"ledger-diff-gate",
	"mint-reachability",
	"notrun",
	"toolchain-parity",
	"witness-earns",
}

// gateProgramWhy is the shared reason; the proof behind it lives in closure.go.
const gateProgramWhy = "a gate program: its own package main under tools/, run at verify time and never built into the appliance — cmd/identuum-idp's build closure holds no tools/ package, re-proved by the closure check whenever this entry is relied on"

// gateProgramEntries renders GateProgramDirs as declarations, one per program,
// each scoped to this repository only.
func gateProgramEntries() []NoReachEntry {
	entries := make([]NoReachEntry, 0, len(GateProgramDirs))
	for _, dir := range GateProgramDirs {
		entries = append(entries, NoReachEntry{Pattern: "tools/" + dir + "/**", Why: gateProgramWhy, ThisRepoOnly: true})
	}
	return entries
}

// IsGateProgramEntry reports whether pattern is one of the gate-program
// declarations, i.e. an entry whose truth rests on the closure proof.
func IsGateProgramEntry(pattern string) bool {
	for _, e := range gateProgramEntries() {
		if e.Pattern == pattern {
			return true
		}
	}
	return false
}

// NoReachSet is the committed declaration. Order does not matter; a path is
// no-reach if ANY entry matches it. The gate-program entries are appended
// after the hand-written ones so the earlier declarations stay as they were.
var NoReachSet = append(baseNoReachSet, gateProgramEntries()...)

// baseNoReachSet is every declaration that needs no proof beyond its reason.
var baseNoReachSet = []NoReachEntry{
	{Pattern: ".github/**", Why: "CI configuration: read by GitHub, never compiled, never served"},
	{Pattern: "docs/**", Why: "prose"},
	{Pattern: "**/*.md", Why: "prose (covers RULE-FLOOR.md and every README)"},
	{Pattern: "ledger-amendments.json", Why: "the amendment manifest, read by ledger-diff-gate at verify time"},
	{Pattern: "GATE-RUN*.txt", Why: "gate records: written by the gates, read by gate-witness check"},
	{Pattern: "MINT-STATE.json", Why: "the RETIRED marker (THE-ONE-MINT-RECORD, 2026-09-12): the classifier now reads the mint's own record in the sibling and neither reads nor writes this file. The entry stays so a stale copy in an older checkout is never judged reaching"},
	{Pattern: "wiki/**", Why: "a sibling repository's prose"},
	{Pattern: "**/*_test.go", Why: "the Go toolchain excludes *_test.go from every non-test build"},
	{Pattern: "CI-WITNESS.txt", Why: "the committed CI claim: fetched from a CI artifact, judged by ci-witness at verify time, never compiled or served"},
	{Pattern: "conformance/**", Why: "the OpenID harness and its floors; nothing under it ships: the runner, the plan fixtures and the expected-failure files drive a disposable appliance the harness builds and destroys itself, and none of it is compiled into the binary or served (owner decision, THE-HONEST-HARNESS-AND-THE-PUSH, 2026-09-07)"},
	// THE-SIX-SMALL-ONES (2026-09-16): the gate scripts. PROVED, not
	// trusted, and re-measured on every test run (reach_test.go): the image
	// recipe deployment/Dockerfile.local copies the context into the BUILDER
	// stage only (`COPY . .`, so embed.FS sources are present) and RUNs
	// nothing under scripts/; its RUNTIME stage copies only `--from=`
	// artifacts (the binary, certs, passwd/group, the data dir); and the Go
	// toolchain's own answer, `go list -f {{.EmbedPatterns}} ./...`, names
	// only migrations/*.sql — nothing under scripts/ is compiled into any
	// package, and a .sh file cannot be one. Three scripts joined this week
	// and each forced a full mint for a change no appliance could see.
	// ThisRepoOnly: the proof is about THIS module's image; the sibling's
	// scripts/ stays reaching until it proves its own.
	{Pattern: "scripts/**", Why: "the gate scripts: never copied into the runtime image (only --from= artifacts are), never run by the image build, never embedded (go list EmbedPatterns names only migrations/*.sql) — proved by reach_test.go on every run", ThisRepoOnly: true},
	// THE-EIGHT-QUICK-ONES, OSS 3 (2026-09-16): the SIBLING's Makefile. Its
	// recipes run on a developer's machine and in CI; the ui image is built by
	// identuum-ui/Dockerfile, whose RUNs are npm/pnpm and never make, whose
	// runner stage copies only `--from=` artifacts, and whose package.json
	// scripts never invoke make — so no recipe reaches the image the appliance
	// serves. PROVED, not trusted: ProveSiblingMakefileUnreachable re-reads the
	// sibling's Dockerfile and package.json whenever a decision relies on this
	// entry (fails closed if the sibling is absent), and reach_test.go on every
	// run where the sibling checkout exists. SiblingOnly: THIS module's
	// Makefile builds the appliance image and stays reaching.
	{Pattern: SiblingMakefileEntry, Why: "the sibling's Makefile: its recipes never reach identuum-ui's image — the Dockerfile RUNs no make, its runner stage copies only --from= artifacts, package.json scripts invoke no make — proved by ProveSiblingMakefileUnreachable at every reliant decision and by reach_test.go", SiblingOnly: true},
	// THE-LEGATTUS-THAT-LEAVES-THE-TREE-ALONE (2026-09-16): Legattus v0.1.4
	// writes ONE file into the consumer's tree, the committed policy, read by
	// Legattus at its own stages and by nothing the appliance builds or
	// serves. Proved like scripts/** and re-measured by reach_test.go on every
	// run: the runtime stage of deployment/Dockerfile.local copies only
	// --from= artifacts and names no Legattus path, and `go list -f
	// {{.EmbedPatterns}}` embeds no such file. ThisRepoOnly: the proof is about
	// this module's image; a sibling's policy stays reaching until it proves
	// its own.
	{Pattern: ".legattus-policy.json", Why: "Legattus's committed policy: read by Legattus, never copied into the runtime image (only --from= artifacts are), never embedded (go list EmbedPatterns names only migrations/*.sql) — proved by reach_test.go on every run", ThisRepoOnly: true},
}

// SiblingPrefixes are the namespaces main.go puts in front of a sibling
// repository's paths. An entry is matched against the path WITHOUT its
// namespace, so the one declaration governs both repositories; the reported
// path keeps the namespace. Only a listed prefix is stripped — an unlisted
// first segment is a directory like any other.
var SiblingPrefixes = []string{"identuum-ui/"}

// localPath returns p as the repository it came from would name it.
func localPath(p string) string {
	for _, prefix := range SiblingPrefixes {
		if rest, ok := strings.CutPrefix(p, prefix); ok {
			return rest
		}
	}
	return p
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
		local := localPath(p)
		for _, e := range set {
			if e.ThisRepoOnly && local != p {
				// A namespaced sibling path: this entry is about THIS
				// repository's build closure and says nothing about the sibling.
				continue
			}
			if e.SiblingOnly && local == p {
				// This repository's own path: the entry is about the sibling's
				// image and says nothing about this module.
				continue
			}
			if matchPath(e.Pattern, local) {
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
	if d.Required {
		return "check OK: mint-reachability MINT REQUIRED — " + d.Summary()
	}
	return "check OK: mint-reachability SKIPPABLE — " + d.Summary()
}

// Summary is the justification without the verdict prefix: what changed and
// why each path was (or was not) covered. The -e2e-record mode prints one
// per repository.
func (d Decision) Summary() string {
	if len(d.Changed) == 0 {
		return "no change since the last minted witness"
	}
	if d.Required {
		return fmt.Sprintf("%d of %d changed path(s) reach the appliance: %s",
			len(d.Reaching), len(d.Changed), strings.Join(clip(d.Reaching, 8), ", "))
	}
	var justified []string
	for _, p := range d.Changed {
		justified = append(justified, fmt.Sprintf("%s [%s]", p, d.NoReach[p]))
	}
	return fmt.Sprintf("all %d changed path(s) are declared no-reach: %s",
		len(d.Changed), strings.Join(justified, "; "))
}

func clip(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("…and %d more", len(s)-n))
}
