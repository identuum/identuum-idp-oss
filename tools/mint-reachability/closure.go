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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// SiblingMakefileEntry is the one sibling-only declaration: identuum-ui's
// Makefile (THE-EIGHT-QUICK-ONES, OSS 3, 2026-09-16). The ui's Makefile is
// its gate and harness entry point (`make verify`, `make e2e-full`) and is
// never read by `next`, never copied into the ui image's runner stage and
// never run by the image build. Like the gate-program entries it is proved
// rather than trusted: ProveSiblingMakefileUnreachable re-reads the sibling's
// Dockerfile and package.json whenever a decision relies on it, and
// reach_test.go re-measures it wherever the sibling checkout is present.
const SiblingMakefileEntry = "Makefile"

// ProveSiblingMakefileUnreachable proves, from the sibling checkout at uiDir,
// that its Makefile cannot reach the appliance image or binary: the ui image
// recipe (Dockerfile) never RUNs make and its runner stage copies only
// `--from=` artifacts, and package.json's scripts — what `pnpm build` and
// `next dev` execute — never invoke make. It fails CLOSED: an unreadable
// recipe is not a proof, and the harness treats undecidable as MINT REQUIRED.
func ProveSiblingMakefileUnreachable(uiDir string) (string, error) {
	dockerfile, err := os.ReadFile(filepath.Join(uiDir, "Dockerfile"))
	if err != nil {
		return "", fmt.Errorf("sibling Makefile proof: cannot read the ui image recipe: %v", err)
	}
	var runtimeStage bool
	for _, line := range strings.Split(string(dockerfile), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "FROM ") {
			runtimeStage = strings.HasSuffix(l, " AS runner")
		}
		if strings.HasPrefix(l, "RUN ") && makeInvocation.MatchString(l) {
			return "", fmt.Errorf("sibling Makefile proof: the ui image build RUNs make — identuum-ui/Makefile reaches the image: %q", l)
		}
		if runtimeStage && (strings.HasPrefix(l, "COPY ") || strings.HasPrefix(l, "ADD ")) && !strings.Contains(l, "--from=") {
			return "", fmt.Errorf("sibling Makefile proof: the ui runner stage copies from the build context, so the Makefile could ship: %q", l)
		}
	}
	pkg, err := os.ReadFile(filepath.Join(uiDir, "package.json"))
	if err != nil {
		return "", fmt.Errorf("sibling Makefile proof: cannot read the ui package manifest: %v", err)
	}
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pkg, &manifest); err != nil {
		return "", fmt.Errorf("sibling Makefile proof: the ui package manifest is not JSON: %v", err)
	}
	for name, cmd := range manifest.Scripts {
		if makeInvocation.MatchString(cmd) {
			return "", fmt.Errorf("sibling Makefile proof: package.json script %q invokes make — identuum-ui/Makefile reaches what the app runs: %q", name, cmd)
		}
	}
	return "identuum-ui/Makefile does not ship: the ui image build never runs make, its runner stage copies only --from= artifacts, and no package.json script invokes make", nil
}

// makeInvocation matches a shell command that runs make (`make`, `make -C`,
// `gmake`), as a whole word, anywhere in the line.
var makeInvocation = regexp.MustCompile(`(^|[\s;&|(])g?make(\s|$)`)

// reliesOnSiblingMakefile reports whether the decision excused a path through
// the sibling-only Makefile entry, so its proof must be re-run first.
func reliesOnSiblingMakefile(d Decision) bool {
	for _, pattern := range d.NoReach {
		if pattern == SiblingMakefileEntry {
			return true
		}
	}
	return false
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
