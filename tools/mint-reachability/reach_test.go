package main

// reach_test.go — RULE: MINT-REACHABILITY-1.
//
// The failure this rule exists to prevent is a change that reaches the
// running appliance shipping without a mint. So every subtest is a way the
// classifier could say SKIPPABLE when it must not: a source file, a
// dependency bump, a deployment file, a path nobody declared, and — the one
// that would quietly disarm the whole thing — a no-reach entry widened until
// it covers real code.

import (
	"os"
	"strings"
	"testing"
)

// RULE: MINT-REACHABILITY-1
func TestRuleMintReachability1_OnlyDeclaredNoReachSkips_EverythingElseMints(t *testing.T) {
	t.Run("the declared no-reach set skips, and every path is justified by name", func(t *testing.T) {
		changed := []string{
			".github/workflows/ci.yml",
			"docs/DEPENDENCY-CURRENCY.md",
			"RULE-FLOOR.md",
			"ledger-amendments.json",
			"GATE-RUN.txt",
			"MINT-STATE.json",
			"cmd/identuum-idp/gate_witness_clean_head_test.go",
		}
		d := Decide(changed, NoReachSet)
		if d.Required {
			t.Fatalf("a documentation/CI/test-only change demanded a mint: %v", d.Reaching)
		}
		if len(d.NoReach) != len(changed) {
			t.Fatalf("not every path was justified: %+v", d.NoReach)
		}
		line := d.Line()
		if !strings.HasPrefix(line, "check OK: mint-reachability SKIPPABLE") {
			t.Fatalf("evidence line does not state the decision: %q", line)
		}
		for _, p := range changed {
			if !strings.Contains(line, p) {
				t.Fatalf("the skip does not name %s — a skip nobody can audit does not exist", p)
			}
		}
	})

	t.Run("source, deps, deployment and the harness all REQUIRE the mint", func(t *testing.T) {
		for _, p := range []string{
			"internal/service/local_login_service.go",
			"cmd/identuum-idp/main.go",
			"auth/acr_login.go",
			"go.mod",
			"go.sum",
			"deployment/Dockerfile.local",
			"Makefile",
			"e2e-full/scripts/full-run.sh",
			"src/app/login/page.tsx",
		} {
			d := Decide([]string{p}, NoReachSet)
			if !d.Required {
				t.Errorf("%s classified SKIPPABLE — it can reach the appliance", p)
			}
		}
	})

	t.Run("go.mod is NOT prose just because it sits beside prose", func(t *testing.T) {
		d := Decide([]string{"docs/README.md", "go.mod"}, NoReachSet)
		if !d.Required {
			t.Fatal("a dependency bump rode in under a documentation change")
		}
		if len(d.Reaching) != 1 || d.Reaching[0] != "go.mod" {
			t.Fatalf("reaching set = %v, want exactly [go.mod]", d.Reaching)
		}
	})

	t.Run("an UNKNOWN path fails closed and is named", func(t *testing.T) {
		d := Decide([]string{"something/nobody/declared.bin"}, NoReachSet)
		if !d.Required {
			t.Fatal("an undeclared path was treated as harmless — the classifier must fail closed")
		}
		if len(d.Unknown) != 1 {
			t.Fatalf("unknown set = %v, want the one path", d.Unknown)
		}
		if !strings.Contains(d.Line(), "something/nobody/declared.bin") {
			t.Fatalf("the line does not name the unknown path: %q", d.Line())
		}
	})

	t.Run("a *_test.go file skips but a non-test file with test in its name does NOT", func(t *testing.T) {
		if Decide([]string{"internal/service/mfa_verifier_test.go"}, NoReachSet).Required {
			t.Error("a _test.go file demanded a mint; the Go toolchain never builds it into the binary")
		}
		for _, p := range []string{"internal/service/testing.go", "internal/testsupport/helper.go"} {
			if !Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s classified SKIPPABLE — it is compiled into the binary", p)
			}
		}
	})

	t.Run("an empty change set is skippable and says why", func(t *testing.T) {
		d := Decide(nil, NoReachSet)
		if d.Required {
			t.Fatal("nothing changed and the mint was still demanded")
		}
		if !strings.Contains(d.Line(), "no change since the last minted witness") {
			t.Fatalf("line = %q", d.Line())
		}
	})

	t.Run("A WIDENED ENTRY MUST NOT SWALLOW REAL CODE", func(t *testing.T) {
		// The disarming mutation, held explicitly: if someone broadens an
		// entry — `docs/**` to `**`, or `**/*.md` to `**/*` — real source
		// must still classify as reaching. This subtest is what turns that
		// edit red.
		for _, widened := range []string{"**", "**/*", "*"} {
			set := append([]NoReachEntry{{Pattern: widened, Why: "widened by mistake"}}, NoReachSet...)
			d := Decide([]string{"internal/service/local_login_service.go"}, set)
			if !d.Required {
				t.Errorf("no-reach entry %q swallowed a source file — the mint would be skipped on a change that reaches the appliance", widened)
			}
		}
	})

	t.Run("matchPath does not let a prefix entry escape its directory", func(t *testing.T) {
		cases := map[string]bool{
			"docs/a/b.txt":     true,  // under docs/
			"docs":             true,  // the directory itself
			"docsy/evil.go":    false, // NOT under docs/
			"internal/docs.go": false,
		}
		for p, want := range cases {
			if got := matchPath("docs/**", p); got != want {
				t.Errorf("matchPath(docs/**, %s) = %v, want %v", p, got, want)
			}
		}
	})

	t.Run("the SAME declaration applies under the sibling's namespace — a record is a record in either repository", func(t *testing.T) {
		// THE-RECORD-ONLY-CLOSE (2026-09-07). main.go prefixes the ui's paths
		// with identuum-ui/ so a report can never confuse the repositories;
		// the entries were then matched against the PREFIXED path, so the
		// root-anchored GATE-RUN*.txt and the literal ledger-amendments.json
		// never matched a ui record, and a record-only ui commit read as
		// REACHING. Two wiki closes were refused on commits that cannot change
		// e2e behaviour. The prefix is a namespace, not a directory: strip it
		// and judge the path as the repository it came from would.
		recordOnly := []string{
			"identuum-ui/GATE-RUN.txt",
			"identuum-ui/GATE-RUN.e2e-full.txt",
			"identuum-ui/ledger-amendments.json",
			"identuum-ui/CI-WITNESS.txt",
			"identuum-ui/README.md",
			"CI-WITNESS.txt",
		}
		d := Decide(recordOnly, NoReachSet)
		if d.Required {
			t.Fatalf("a record-only change demanded a mint: %v", d.Reaching)
		}
		if len(d.NoReach) != len(recordOnly) {
			t.Fatalf("not every record path was justified: %+v", d.NoReach)
		}
		for _, p := range recordOnly {
			if !strings.Contains(d.Line(), p) {
				t.Fatalf("the skip does not name %s under its namespace: %q", p, d.Line())
			}
		}
		for _, p := range []string{
			"identuum-ui/src/app/login/page.tsx",
			"identuum-ui/e2e-full/scripts/full-run.sh",
			"identuum-ui/Makefile",
			"identuum-ui/package.json",
			"identuum-ui/something/nobody/declared.bin",
		} {
			if !Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s classified SKIPPABLE — it reaches the appliance", p)
			}
		}
		// Only a DECLARED sibling is a namespace. An unknown first segment is
		// a directory like any other, and a record name under it is unknown.
		if !Decide([]string{"identuum-idp-ce/GATE-RUN.txt"}, NoReachSet).Required {
			t.Error("an undeclared namespace was stripped — only a declared sibling prefix may be")
		}
	})

	t.Run("an e2e record is judged only when green, finished and pinned to both heads", func(t *testing.T) {
		// The wiki's witness-ui-e2e falls through to this tool when achta's
		// witness check fails; the tool must therefore refuse to judge a record
		// that failed for any reason but staleness. Anything short of a green,
		// finished record with both heads is undecidable, never accepted.
		good := "gate: e2e-full\nrepo-head: 6dfca4e\nplan: a\ntarget: a exit=0\nfinished: 2026-09-06T00:00:00Z\ntree: sha256=abc\nxrepo: identuum-idp-oss head=5c08c1a tree=sha256:def\nresult: green\n"
		heads, err := parseE2ERecord(good)
		if err != nil {
			t.Fatalf("a green, finished, pinned record was refused: %v", err)
		}
		if heads.UI != "6dfca4e" || heads.Sibling != "5c08c1a" {
			t.Fatalf("heads = %+v, want ui 6dfca4e and sibling 5c08c1a", heads)
		}
		for name, bad := range map[string]string{
			"red":          strings.Replace(good, "result: green", "result: red", 1),
			"no result":    strings.Replace(good, "result: green\n", "", 1),
			"unfinished":   strings.Replace(good, "finished: 2026-09-06T00:00:00Z\n", "", 1),
			"no ui head":   strings.Replace(good, "repo-head: 6dfca4e\n", "", 1),
			"no xrepo pin": strings.Replace(good, "xrepo: identuum-idp-oss head=5c08c1a tree=sha256:def\n", "", 1),
		} {
			if _, err := parseE2ERecord(bad); err == nil {
				t.Errorf("a %s record was accepted for judging — it must be undecidable", name)
			}
		}
	})

	t.Run("make mint-decide states the contract a CALLER sees, never a code make rewrites", func(t *testing.T) {
		// THE-TWO-JUDGE-CONTRACTS (2026-09-06). The recipe's comment said "its
		// exit code is the answer"; make turns every non-zero recipe exit into
		// its own exit 2, and `go run` had already collapsed the tool's 10 to
		// 1, so a dispatcher testing for 10 never fired and a mint was
		// dispatched by hand. This subtest keeps that sentence out of the
		// Makefile and keeps the recipe in the shape that makes the tool's
		// real code visible: the tool is BUILT (not `go run`), its exit is
		// captured, and it is printed on a line a caller can read.
		src, err := os.ReadFile("../../Makefile")
		if err != nil {
			t.Fatalf("read Makefile: %v", err)
		}
		makefile := string(src)
		if strings.Contains(makefile, "its exit code is the answer") {
			t.Fatal("the Makefile claims a recipe's exit code is the answer — make rewrites every non-zero recipe exit to 2, so no caller can read it")
		}
		recipe := makefileRecipe(t, makefile, "mint-decide")
		for _, want := range []string{
			"go build -o",                 // the tool is built, so its exit code survives
			"rc=$$?",                      // and captured
			"mint-decide: tool exit $$rc", // and printed for the caller
			"exit $$rc",                   // make still fails on anything but 0 (fail closed)
		} {
			if !strings.Contains(recipe, want) {
				t.Errorf("mint-decide recipe lacks %q:\n%s", want, recipe)
			}
		}
		if strings.Contains(recipe, "go run ./tools/mint-reachability") {
			t.Errorf("mint-decide runs the classifier through `go run`, which collapses exit 10 to 1:\n%s", recipe)
		}
		// test-full's own branch is the fail-closed 0-versus-non-zero one, and
		// must stay that way: only an explicit 0 skips.
		testFull := makefileRecipe(t, makefile, "test-full")
		if !strings.Contains(testFull, "if go run ./tools/mint-reachability --repo .; then") {
			t.Errorf("test-full no longer branches on the classifier's 0-versus-non-zero exit:\n%s", testFull)
		}
	})

	t.Run("the conformance harness and its floors do not reach the appliance, but source beside them still does", func(t *testing.T) {
		// THE-HONEST-HARNESS-AND-THE-PUSH (owner decision, 2026-09-07):
		// conformance/** is the OpenID conformance harness — its runner, the
		// plan fixtures and the expected-failure floors. Nothing under it is
		// compiled into the binary or served; the harness stands up its own
		// disposable appliance, which the e2e mint never sees. A floor row
		// cannot change what the mint measures, so demanding a ten-minute
		// mint for one is a false signal, not caution.
		for _, p := range []string{
			"conformance/expected-failures-config.json",
			"conformance/run.sh",
			"conformance/plan-basic.json",
			"conformance/PIN",
		} {
			if Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s demanded the full e2e mint — nothing under conformance/ ships", p)
			}
		}
		// The entry must not become a doorway: real source changed in the same
		// commit still reaches, and is named alone.
		d := Decide([]string{"conformance/run.sh", "internal/service/local_login_service.go"}, NoReachSet)
		if !d.Required {
			t.Fatal("a source change rode in under a conformance/ change")
		}
		if len(d.Reaching) != 1 || d.Reaching[0] != "internal/service/local_login_service.go" {
			t.Fatalf("reaching set = %v, want exactly [internal/service/local_login_service.go]", d.Reaching)
		}
		// And a prefix is not a directory: a sibling path that merely starts
		// with the same letters must still reach.
		if !Decide([]string{"conformance-notes/plan.go"}, NoReachSet).Required {
			t.Error("conformance-notes/plan.go escaped under the conformance/ entry")
		}
	})
}

// makefileRecipe returns the recipe lines of a Makefile target: everything
// indented under `name:` up to the first line that is neither blank nor
// indented.
func makefileRecipe(t *testing.T, src, name string) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, name+":") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("Makefile has no %s target", name)
	}
	var b strings.Builder
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if l != "" && !strings.HasPrefix(l, "\t") && !strings.HasPrefix(l, " ") {
			break
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}
