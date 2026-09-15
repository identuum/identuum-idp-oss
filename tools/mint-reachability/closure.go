package main

// closure.go — the proof behind the tools/<program>/** entries
// (THE-TOOLS-THAT-CANNOT-REACH, 2026-09-13).
//
// A declaration nothing re-checks is how stale records are made here, and
// this one would silently excuse a real reach: if a gate program were ever
// imported by the product, a change to it WOULD reach the appliance while the
// entry said it could not. So the entry is not trusted, it is proved, from
// the tool's own evidence: `go list -deps ./cmd/...` is the build closure of
// what deployment/Dockerfile.local compiles (`go build ./cmd/identuum-idp`),
// and no package under a declared program directory may appear in it. The
// proof runs whenever a decision relies on a gate-program entry (main.go),
// on demand with -prove-no-reach, and on every test run (closure_test.go).
// It fails CLOSED: a proof that cannot run is undecidable, which the harness
// treats as MINT REQUIRED.

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// applianceRoots is what the appliance builds. deployment/Dockerfile.local
// compiles ./cmd/identuum-idp; ./cmd/... is the closure's root pattern so a
// second command under cmd/ would be covered the day it appears.
const applianceRoots = "./cmd/..."

// applianceClosure runs `go list -deps` over the appliance roots in repoDir
// and returns the directories of the closure's packages that live INSIDE the
// repository (relative, slash-separated, sorted) and the closure's total size.
// Packages outside the repository — the standard library, the module cache —
// cannot be a tools/ directory of this module and are counted, not listed.
func applianceClosure(repoDir string) (inside []string, total int, err error) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.Dir}}", applianceRoots)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		detail := ""
		if ee, ok := err.(*exec.ExitError); ok {
			detail = ": " + strings.TrimSpace(string(ee.Stderr))
		}
		return nil, 0, fmt.Errorf("go list -deps %s in %s failed%s (%v)", applianceRoots, repoDir, detail, err)
	}
	root, err := filepath.Abs(repoDir)
	if err != nil {
		return nil, 0, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		rel, err := filepath.Rel(root, line)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		inside = append(inside, filepath.ToSlash(rel))
	}
	sort.Strings(inside)
	return inside, total, nil
}

// embedPatterns asks the Go toolchain which files any package of the module
// embeds (`go list -f {{.EmbedPatterns}} ./...`): the authoritative answer to
// "is this non-Go path compiled into the binary?" — the proof behind the
// scripts/** entry (THE-SIX-SMALL-ONES, 2026-09-16), re-measured by its test.
func embedPatterns(repoDir string) ([]string, error) {
	cmd := exec.Command("go", "list", "-f", "{{range .EmbedPatterns}}{{.}}\n{{end}}", "./...")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		detail := ""
		if ee, ok := err.(*exec.ExitError); ok {
			detail = ": " + strings.TrimSpace(string(ee.Stderr))
		}
		return nil, fmt.Errorf("go list embed patterns in %s failed%s (%v)", repoDir, detail, err)
	}
	var patterns []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			patterns = append(patterns, line)
		}
	}
	return patterns, nil
}

// reachableGatePrograms is the pure core of the proof: which declared program
// directories appear in the closure, as the directory itself or beneath it.
// An empty answer is the proof; a non-empty one names the unsound entries.
func reachableGatePrograms(closureDirs []string, programs []string) []string {
	var hit []string
	for _, prog := range programs {
		dir := "tools/" + prog
		for _, d := range closureDirs {
			if d == dir || strings.HasPrefix(d, dir+"/") {
				hit = append(hit, fmt.Sprintf("%s (built as %s)", dir, d))
				break
			}
		}
	}
	return hit
}

// ProveGateProgramsUnreachable proves, from `go list -deps` in repoDir, that
// no declared gate program is in the appliance's build closure. It returns
// the one evidence line on success; on failure the error names every
// declared program the appliance builds, so the gate that fails says which.
func ProveGateProgramsUnreachable(repoDir string) (string, error) {
	inside, total, err := applianceClosure(repoDir)
	if err != nil {
		return "", fmt.Errorf("no-reach proof could not run: %w", err)
	}
	if hit := reachableGatePrograms(inside, GateProgramDirs); len(hit) > 0 {
		return "", fmt.Errorf("no-reach proof FAILED: declared gate program(s) ARE in the appliance's build closure (go list -deps %s): %s — the declaration is unsound; remove the import or the entry",
			applianceRoots, strings.Join(hit, ", "))
	}
	return fmt.Sprintf("check OK: mint-reachability no-reach proof — %d gate program(s) declared under tools/, none in the build closure of %s (%d package(s), %d of them in this repository)",
		len(GateProgramDirs), applianceRoots, total, len(inside)), nil
}

// reliesOnGateProgram reports whether a decision excused any path under a
// gate-program entry — the case in which the entry's proof must hold.
func reliesOnGateProgram(d Decision) bool {
	for _, pattern := range d.NoReach {
		if IsGateProgramEntry(pattern) {
			return true
		}
	}
	return false
}
