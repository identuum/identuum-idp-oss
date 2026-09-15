package main

// closure_test.go — RULE: TOOLS-NO-REACH-1 (THE-TOOLS-THAT-CANNOT-REACH,
// 2026-09-13).
//
// The gate programs under tools/ are declared no-reach, and the declaration
// is only as good as its proof. Every subtest is a way the declaration could
// lie: a gate program still charged the mint (the entry missing), a product
// file or a script or the Makefile excused beside it (the entry too wide), a
// sibling path excused by an entry about THIS module's closure, and — the
// one that would quietly excuse a real reach — a declared program that the
// appliance builds while the proof still says it does not. Everything here
// is hermetic: the module the proof runs `go list` against is a throwaway
// fixture with no dependencies, and no mint is run by any test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureModule writes a minimal Go module: cmd/app that either imports the
// library under tools/grype-gate (importsGate) or does not. It returns the
// module root. The library is a real importable package so the import is a
// real reach, not a sentinel.
func fixtureModule(t *testing.T, importsGate bool) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.test/fixture\n\ngo 1.24\n")
	write("tools/grype-gate/gate.go", "package gate\n\n// Verdict is what a product must never depend on.\nfunc Verdict() string { return \"green\" }\n")
	write("internal/product/product.go", "package product\n\n// Serve is the appliance.\nfunc Serve() string { return \"serving\" }\n")
	if importsGate {
		write("cmd/app/main.go", "package main\n\nimport (\n\t\"example.test/fixture/internal/product\"\n\t\"example.test/fixture/tools/grype-gate\"\n)\n\nfunc main() { println(product.Serve(), gate.Verdict()) }\n")
	} else {
		write("cmd/app/main.go", "package main\n\nimport \"example.test/fixture/internal/product\"\n\nfunc main() { println(product.Serve()) }\n")
	}
	return dir
}

// moduleTree is a fixture module that is also a git repository with one
// commit, so decideFromRecord can judge paths changed since that head.
func moduleTree(t *testing.T, importsGate bool) (string, string) {
	t.Helper()
	dir := fixtureModule(t, importsGate)
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	return dir, gitIn(t, dir, "rev-parse", "--short", "HEAD")
}

// commitGateSource commits a VALID Go file into the fixture's gate program,
// so the tree still lists: the proof, not a parse error, must be what
// decides the unsound case.
func commitGateSource(t *testing.T, dir, path string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.WriteFile(full, []byte("package gate\n\n// Subject was added after the record.\nfunc Subject() string { return \"dir\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", path)
	gitIn(t, dir, "commit", "-q", "-m", "change "+path)
}

// RULE: TOOLS-NO-REACH-1
func TestRuleToolsNoReach1_GateProgramsAreDeclaredAndProvedUnreachable(t *testing.T) {
	t.Run("a change to a declared gate program does NOT require a mint, and is justified by its own entry", func(t *testing.T) {
		var changed []string
		for _, prog := range GateProgramDirs {
			changed = append(changed, "tools/"+prog+"/main.go")
		}
		changed = append(changed, "tools/grype-gate/subject.go", "tools/api-docgen/testdata/endpoints.golden.yaml")
		d := Decide(changed, NoReachSet)
		if d.Required {
			t.Fatalf("a gate-program change demanded a mint: %v", d.Reaching)
		}
		if len(d.NoReach) != len(changed) {
			t.Fatalf("not every gate-program path was justified: %+v", d.NoReach)
		}
		for p, pattern := range d.NoReach {
			if !IsGateProgramEntry(pattern) || !strings.HasPrefix(p, strings.TrimSuffix(pattern, "/**")+"/") {
				t.Errorf("%s was excused by %q, not by its own gate-program entry", p, pattern)
			}
		}
	})

	t.Run("a product file, a deployment file, the Makefile, go.mod and the root tools helper package still DO", func(t *testing.T) {
		// THE-SIX-SMALL-ONES (2026-09-16): this list named scripts/gate-witness.sh
		// as its example of a reaching non-tool path; scripts/** is now declared
		// no-reach with its own proof (reach_test.go), so the example is the
		// compose file the appliance runs from instead.
		for _, p := range []string{
			"internal/service/local_login_service.go",
			"cmd/identuum-idp/main.go",
			"deployment/docker-compose.dev.yml",
			"Makefile",
			"go.mod",
			"tools/tools.go",
			"tools/README.md.go",
			"toolsy/grype-gate/main.go",
		} {
			d := Decide([]string{p}, NoReachSet)
			if !d.Required {
				t.Errorf("%s classified SKIPPABLE — it is not a declared gate program", p)
			}
		}
		// The entry must not become a doorway: source changed beside a gate
		// program still reaches, and is named alone.
		d := Decide([]string{"tools/grype-gate/main.go", "internal/service/local_login_service.go"}, NoReachSet)
		if !d.Required || len(d.Reaching) != 1 || d.Reaching[0] != "internal/service/local_login_service.go" {
			t.Fatalf("reaching set = %v, want exactly the source file", d.Reaching)
		}
	})

	t.Run("a gate-program entry is about THIS module's closure and excuses nothing under the sibling's namespace", func(t *testing.T) {
		for _, p := range []string{"identuum-ui/tools/notrun/x.ts", "identuum-ui/tools/grype-gate/main.go"} {
			if !Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s was excused by an entry proved only for identuum-idp-oss's build closure", p)
			}
		}
	})

	t.Run("the proof's core names a declared program the closure contains, and nothing when it does not", func(t *testing.T) {
		closure := []string{"cmd/identuum-idp", "internal/api", "internal/service", "tools/grype-gate", "tools/grype-gate/sub"}
		hit := reachableGatePrograms(closure, GateProgramDirs)
		if len(hit) != 1 || !strings.HasPrefix(hit[0], "tools/grype-gate (built as tools/grype-gate)") {
			t.Fatalf("reachable = %v, want exactly tools/grype-gate named once", hit)
		}
		if hit := reachableGatePrograms([]string{"cmd/identuum-idp", "internal/api", "tools/grype-gatekeeper"}, GateProgramDirs); len(hit) != 0 {
			t.Fatalf("a directory that merely starts with a program's name was reported reachable: %v", hit)
		}
	})

	t.Run("the proof FAILS on a module whose appliance imports a declared program, and PASSES on one that does not", func(t *testing.T) {
		bad := fixtureModule(t, true)
		if line, err := ProveGateProgramsUnreachable(bad); err == nil {
			t.Fatalf("the proof passed on a module whose cmd/ imports tools/grype-gate: %s", line)
		} else if !strings.Contains(err.Error(), "tools/grype-gate") || !strings.Contains(err.Error(), "no-reach proof FAILED") {
			t.Fatalf("the failure does not name the reachable program: %v", err)
		}
		good := fixtureModule(t, false)
		line, err := ProveGateProgramsUnreachable(good)
		if err != nil {
			t.Fatalf("the proof failed on a module whose cmd/ imports no gate program: %v", err)
		}
		if !strings.HasPrefix(line, "check OK: mint-reachability no-reach proof") || !strings.Contains(line, "none in the build closure of ./cmd/...") {
			t.Fatalf("the proof line does not state the proof: %q", line)
		}
	})

	t.Run("the mint decision relies on the entry only while the proof holds — an unsound tree is UNDECIDABLE, never satisfied", func(t *testing.T) {
		ui, uiHead := newTree(t)
		good, goodHead := moduleTree(t, false)
		commitGateSource(t, good, "tools/grype-gate/subject.go")
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, goodHead), good, ui)
		if code != ExitSkippable || !strings.Contains(line, "MINT SATISFIED") || !strings.Contains(line, "tools/grype-gate/subject.go [tools/grype-gate/**]") {
			t.Fatalf("a gate-program change on a sound tree must be satisfied by the record; exit %d: %s", code, line)
		}
		bad, badHead := moduleTree(t, true)
		commitGateSource(t, bad, "tools/grype-gate/subject.go")
		line, code = decideFromRecord(writeRecord(t, "green", uiHead, badHead), bad, ui)
		if code != ExitUndecidable || !strings.Contains(line, "no-reach proof FAILED") || !strings.Contains(line, "tools/grype-gate (built as tools/grype-gate)") {
			t.Fatalf("a gate-program change on an UNSOUND tree must be undecidable BY THE PROOF and name the program; exit %d: %s", code, line)
		}
		if strings.Contains(line, "SATISFIED") {
			t.Fatalf("an unsound declaration satisfied the mint: %s", line)
		}
	})

	t.Run("a change that relies on no gate-program entry never runs the proof, so a tree without a module is judged as before", func(t *testing.T) {
		ui, uiHead := newTree(t)
		oss, ossHead := newTree(t)
		commitPath(t, oss, "docs/notes.md")
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, ossHead), oss, ui)
		if code != ExitSkippable || !strings.Contains(line, "MINT SATISFIED") {
			t.Fatalf("a prose-only change on a module-less fixture must still be satisfied; exit %d: %s", code, line)
		}
	})
}

// This repository's own closure, re-proved on every test run. It is the
// standing check the declaration owes: if any package the appliance builds
// ever imports a gate program, this fails and names it. It reads the real
// tree (two directories up from this package) and runs nothing but `go list`.
func TestGateProgramsStayOutsideThisRepositorysApplianceClosure(t *testing.T) {
	line, err := ProveGateProgramsUnreachable(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Log(line)
}
