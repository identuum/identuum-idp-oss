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
	"path/filepath"
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

	t.Run("scripts/** does not ship: no-reach in THIS repository, proved from the image and the module", func(t *testing.T) {
		// THE-SIX-SMALL-ONES (2026-09-16). scripts/ holds the gate scripts —
		// gate-witness.sh, ci-record.sh, verify-check.sh and their tests — and
		// three joined this week, each forcing a full e2e mint because
		// scripts/** was undeclared. The entry is declared ONLY with the proof
		// that nothing under scripts/ reaches the appliance image or binary:
		//   1. deployment/Dockerfile.local copies the whole context into the
		//      BUILDER stage (`COPY . .`, so embed.FS sources are present) and
		//      no RUN there executes anything under scripts/; the RUNTIME stage
		//      copies only `--from=` artifacts (the built binary, certs,
		//      passwd/group, the data dir) — never a scripts/ path;
		//   2. the Go toolchain's own answer, `go list -f {{.EmbedPatterns}}`,
		//      names no pattern under scripts/ — nothing in scripts/ is
		//      compiled into any package, and a .sh file cannot be a package.
		// Both are re-measured here on every test run, so the entry is never
		// trusted on its own; the sibling's scripts/ stays REACHING because the
		// proof is about this module's image (ThisRepoOnly).
		for _, p := range []string{"scripts/gate-witness.sh", "scripts/ci-record.sh", "scripts/verify-check-test.sh"} {
			d := Decide([]string{p}, NoReachSet)
			if d.Required {
				t.Errorf("%s classified as reaching: it is a gate script the appliance never copies nor runs (reaching=%v unknown=%v)", p, d.Reaching, d.Unknown)
			}
		}
		if !Decide([]string{"identuum-ui/scripts/gate-witness.sh"}, NoReachSet).Required {
			t.Error("the sibling's scripts/ was excused by an entry whose proof is about THIS module's image")
		}
		if !Decide([]string{"e2e-full/scripts/full-run.sh"}, NoReachSet).Required {
			t.Error("the e2e harness rode in under scripts/** — it is not under the root scripts/ directory")
		}

		dockerfile, err := os.ReadFile("../../deployment/Dockerfile.local")
		if err != nil {
			t.Fatalf("read the image recipe: %v", err)
		}
		var runtimeStage bool
		for _, line := range strings.Split(string(dockerfile), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") || l == "" {
				continue
			}
			if strings.HasPrefix(l, "FROM ") {
				runtimeStage = strings.HasSuffix(l, " AS runtime")
			}
			if strings.HasPrefix(l, "RUN ") && strings.Contains(l, "scripts/") {
				t.Errorf("the image build RUNS something under scripts/ — scripts/** reaches the image: %q", l)
			}
			if runtimeStage && (strings.HasPrefix(l, "COPY ") || strings.HasPrefix(l, "ADD ")) {
				if !strings.Contains(l, "--from=") {
					t.Errorf("the runtime stage copies from the build context, so scripts/ could ship: %q", l)
				}
				if strings.Contains(l, "scripts/") {
					t.Errorf("the runtime stage copies a scripts/ path: %q", l)
				}
			}
		}
		embeds, err := embedPatterns("../..")
		if err != nil {
			t.Fatalf("go list embed patterns: %v", err)
		}
		for _, e := range embeds {
			if strings.Contains(e, "scripts/") || strings.HasPrefix(e, "scripts") {
				t.Errorf("a package embeds %q — scripts/ is compiled into the binary", e)
			}
		}
	})

	t.Run("the Legattus policy does not ship: no-reach in THIS repository, proved from the image and the module", func(t *testing.T) {
		// THE-LEGATTUS-THAT-LEAVES-THE-TREE-ALONE (2026-09-16). Legattus v0.1.4
		// writes ONE file into the consumer's tree, the committed
		// .legattus-policy.json, read by Legattus at its own stages and by
		// nothing the appliance builds or serves. Declared no-reach with the
		// same two proofs as scripts/**, re-measured here: the runtime stage of
		// deployment/Dockerfile.local copies only --from= artifacts, and the
		// toolchain's embed patterns name no such file. ThisRepoOnly: the
		// proof is about this module's image; a sibling's policy stays reaching
		// until it proves its own.
		if d := Decide([]string{".legattus-policy.json"}, NoReachSet); d.Required {
			t.Errorf(".legattus-policy.json classified as reaching: Legattus's policy is read by Legattus, never built or served (reaching=%v unknown=%v)", d.Reaching, d.Unknown)
		}
		for _, p := range []string{"internal/.legattus-policy.json", ".legattus-policy.json.bak", "identuum-ui/.legattus-policy.json"} {
			if !Decide([]string{p}, NoReachSet).Required {
				t.Errorf("%s rode in under the root policy entry", p)
			}
		}
		dockerfile, err := os.ReadFile("../../deployment/Dockerfile.local")
		if err != nil {
			t.Fatalf("read the image recipe: %v", err)
		}
		var runtimeStage bool
		for _, line := range strings.Split(string(dockerfile), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "#") || l == "" {
				continue
			}
			if strings.HasPrefix(l, "FROM ") {
				runtimeStage = strings.HasSuffix(l, " AS runtime")
			}
			if strings.Contains(l, "legattus") {
				t.Errorf("the image recipe names Legattus: %q", l)
			}
			if runtimeStage && (strings.HasPrefix(l, "COPY ") || strings.HasPrefix(l, "ADD ")) && !strings.Contains(l, "--from=") {
				t.Errorf("the runtime stage copies from the build context, so the policy could ship: %q", l)
			}
		}
		embeds, err := embedPatterns("../..")
		if err != nil {
			t.Fatalf("go list embed patterns: %v", err)
		}
		for _, e := range embeds {
			if strings.Contains(e, "legattus") || strings.Contains(e, "*.json") {
				t.Errorf("a package embeds %q — the policy could be compiled into the binary", e)
			}
		}
	})

	t.Run("the sibling's Makefile does not ship: no-reach for identuum-ui ONLY, proved from its image and its scripts", func(t *testing.T) {
		// THE-EIGHT-QUICK-ONES, OSS 3 (2026-09-16). identuum-ui/Makefile is
		// the ui's gate and harness entry point (`make verify`, `make
		// e2e-full`); a recipe edit there cost a full e2e mint
		// (THE-UI-AUDIT-IN-CI paid one for a NODE default). The entry is
		// declared ONLY with the proof that no ui recipe reaches the
		// appliance image or binary, re-measured here whenever the sibling
		// checkout is present and at decision time by main.go:
		//   1. identuum-ui/Dockerfile — the only ui image recipe — copies the
		//      context into its BUILDER stage (`COPY . .`) and RUNs pnpm, never
		//      make; its RUNNER stage copies only `--from=builder` artifacts;
		//   2. identuum-ui/package.json's scripts — what `pnpm build` and
		//      `next dev` run — never invoke make.
		// The OSS Makefile is NOT declared: it builds the appliance (oss-build).
		if Decide([]string{"identuum-ui/Makefile"}, NoReachSet).Required {
			t.Error("identuum-ui/Makefile classified as reaching: the ui's gate recipes never enter the ui image nor the appliance")
		}
		if !Decide([]string{"Makefile"}, NoReachSet).Required {
			t.Error("this module's Makefile was excused by the sibling-only entry — it builds the appliance and must mint")
		}
		if !Decide([]string{"identuum-ui/Dockerfile"}, NoReachSet).Required {
			t.Error("the sibling's Dockerfile rode in under the Makefile entry")
		}
		d := Decide([]string{"identuum-ui/Makefile", "identuum-ui/src/app/login/page.tsx"}, NoReachSet)
		if !d.Required || len(d.Reaching) != 1 || d.Reaching[0] != "identuum-ui/src/app/login/page.tsx" {
			t.Fatalf("reaching set = %v, want exactly the ui source file", d.Reaching)
		}
		// The proof itself, on fixtures shaped like the ui's recipe: it PASSES
		// on a build that never runs make and whose runner copies only
		// --from= artifacts, and FAILS — naming the line — on each way the
		// Makefile could ship: a RUN that invokes make, a runner-stage COPY
		// from the context, a package.json script that calls make.
		cleanDockerfile := "FROM node AS builder\nWORKDIR /app\nCOPY . .\nRUN pnpm install --frozen-lockfile\nRUN pnpm build\n\nFROM node AS runner\nCOPY --from=builder /app/.next/standalone ./\nCMD [\"node\", \"server.js\"]\n"
		cleanPackage := `{"scripts":{"build":"next build","dev":"next dev","verify":"pnpm typecheck && pnpm build"}}`
		fixture := func(t *testing.T, dockerfile, pkg string) string {
			t.Helper()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
				t.Fatal(err)
			}
			return dir
		}
		if line, err := ProveSiblingMakefileUnreachable(fixture(t, cleanDockerfile, cleanPackage)); err != nil {
			t.Fatalf("the proof must hold on a recipe that never runs make: %v", err)
		} else if !strings.Contains(line, "identuum-ui/Makefile") {
			t.Fatalf("the proof line does not name what it proved: %q", line)
		}
		for _, bad := range []struct{ name, dockerfile, pkg, want string }{
			{"a RUN that invokes make", strings.Replace(cleanDockerfile, "RUN pnpm build", "RUN make build", 1), cleanPackage, "RUNs make"},
			{"a RUN that invokes make -C", strings.Replace(cleanDockerfile, "RUN pnpm build", "RUN make -C . build", 1), cleanPackage, "RUNs make"},
			{"a runner-stage COPY from the context", strings.Replace(cleanDockerfile, "COPY --from=builder /app/.next/standalone ./", "COPY . .", 1), cleanPackage, "copies from the build context"},
			{"a package.json script that calls make", cleanDockerfile, `{"scripts":{"build":"make build"}}`, "invokes make"},
		} {
			_, err := ProveSiblingMakefileUnreachable(fixture(t, bad.dockerfile, bad.pkg))
			if err == nil || !strings.Contains(err.Error(), bad.want) {
				t.Errorf("%s: the proof must FAIL naming it; got %v", bad.name, err)
			}
		}
		if _, err := ProveSiblingMakefileUnreachable(t.TempDir()); err == nil {
			t.Error("an absent recipe is not a proof — the check must fail closed")
		}
		// The real sibling, wherever its checkout is present (a CI runner of
		// this repository has none; the mint decision re-reads it in main.go).
		if _, err := os.Stat("../../../identuum-ui/Dockerfile"); err == nil {
			if line, err := ProveSiblingMakefileUnreachable("../../../identuum-ui"); err != nil {
				t.Fatalf("the sibling Makefile proof does not hold on the real identuum-ui checkout: %v", err)
			} else {
				t.Log(line)
			}
		} else {
			t.Log("identuum-ui checkout absent beside this repository; the real recipe is proved at every mint decision instead")
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
			// identuum-ui/Makefile was in this list until THE-EIGHT-QUICK-ONES
			// (2026-09-16): it is now the SiblingOnly entry, proved in its own
			// subtest below; the ui's Dockerfile keeps the image reaching.
			"identuum-ui/Dockerfile",
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

	t.Run("the gate picks the mint: none, quick or full, and an unmatched path is full", func(t *testing.T) {
		// GATE-TIERS (owner ruling 2026-09-26, platform/gate-cost.md). Every
		// case runs the real decision on two throwaway trees and a green
		// e2e-full record pinned to their first heads; `quick` also writes a
		// green e2e-quick record pinned to their CURRENT heads, so a quick-tier
		// change is paid and a full-tier change is still owed.
		const compose = "# identuum-idp-oss compose\n#   curl -fsSLO https://example.test/old.yml\nservices:\n  idp:\n    # the pinned image\n    image: ghcr.io/x/y:v1@sha256:aaa\n"
		base := []tierCommit{{"oss", "deployment/docker-compose.yml", compose}}
		for _, tc := range []struct {
			name     string
			change   []tierCommit
			quick    bool
			wantCode int
			want     []string
		}{
			{"a compose header comment and a blank line → none",
				[]tierCommit{{"oss", "deployment/docker-compose.yml", strings.Replace(compose, "old.yml\n", "new.yml\n\n", 1)}},
				false, ExitSkippable, []string{"MINT SATISFIED", "tier none", "comment-only"}},
			{"an indented comment inside a service → none",
				[]tierCommit{{"oss", "deployment/docker-compose.yml", strings.Replace(compose, "# the pinned image", "# the image, pinned by digest", 1)}},
				false, ExitSkippable, []string{"MINT SATISFIED", "tier none"}},
			{"the compose image line → full",
				[]tierCommit{{"oss", "deployment/docker-compose.yml", strings.Replace(compose, "sha256:aaa", "sha256:bbb", 1)}},
				true, ExitRequired, []string{"MINT REQUIRED", "tier full", "deployment/docker-compose.yml"}},
			{"a ui component with a green quick record at these heads → quick, paid",
				[]tierCommit{{"ui", "src/components/ui/badge.tsx", "export {}\n"}},
				true, ExitSkippable, []string{"MINT SATISFIED by GATE-RUN.e2e-quick.txt", "tier quick", "identuum-ui/src/components/ui/badge.tsx"}},
			{"a ui component without a quick record → quick, owed",
				[]tierCommit{{"ui", "src/components/ui/badge.tsx", "export {}\n"}},
				false, ExitRequired, []string{"MINT REQUIRED", "tier quick", "e2e-quick"}},
			{"internal/service/claim_service.go → full, a quick record does not pay it",
				[]tierCommit{{"oss", "internal/service/claim_service.go", "package service\n"}},
				true, ExitRequired, []string{"MINT REQUIRED", "tier full", "internal/service/claim_service.go"}},
			{"an unknown path → full (fail closed)",
				[]tierCommit{{"oss", "newdir/thing.go", "package newdir\n"}},
				true, ExitRequired, []string{"MINT REQUIRED", "tier full", "newdir/thing.go"}},
			{"a mixed diff takes the highest tier → full",
				[]tierCommit{{"ui", "src/components/ui/badge.tsx", "export {}\n"}, {"oss", "internal/service/claim_service.go", "package service\n"}},
				true, ExitRequired, []string{"MINT REQUIRED", "tier full"}},
			{"a ui sign-in page → full",
				[]tierCommit{{"ui", "src/app/login/page.tsx", "export {}\n"}},
				true, ExitRequired, []string{"MINT REQUIRED", "tier full"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				record, oss, ui := tierFixture(t, base, tc.change, tc.quick)
				line, code := decideFromRecord(record, oss, ui)
				if code != tc.wantCode {
					t.Fatalf("exit %d, want %d: %s", code, tc.wantCode, line)
				}
				for _, w := range tc.want {
					if !strings.Contains(line, w) {
						t.Errorf("the line must say %q: %s", w, line)
					}
				}
			})
		}

		// The ruled quick list for internal/service (owner ruling 2026-09-26):
		// each listed file is quick; any other service file is full.
		for _, f := range []string{
			"api_resource_service.go", "audit_persistent.go", "domain_dns_verifier.go",
			"org_role_service.go", "organization_domain_service.go",
			"organization_protocol_settings_service.go", "organization_service.go",
			"service_account_admin.go", "service_account_service.go",
			"user_profile_service.go", "scope_template_service.go",
			"user_scope_service.go", "smtp_notifier.go",
		} {
			record, oss, ui := tierFixture(t, nil, []tierCommit{{"oss", "internal/service/" + f, "package service\n"}}, true)
			if line, code := decideFromRecord(record, oss, ui); code != ExitSkippable || !strings.Contains(line, "tier quick") {
				t.Errorf("internal/service/%s is on the ruled quick list: exit %d: %s", f, code, line)
			}
		}
		record, oss, ui := tierFixture(t, nil, []tierCommit{{"oss", "internal/service/local_login_service.go", "package service\n"}}, true)
		if line, code := decideFromRecord(record, oss, ui); code != ExitRequired || !strings.Contains(line, "tier full") {
			t.Errorf("an unlisted service file must be full: exit %d: %s", code, line)
		}

		// A '#' line inside a YAML block scalar is data, not a comment: the
		// value the appliance reads changes, so it stays full.
		const scalar = "configs:\n  ui:\n    content: |\n      {\"a\": 1}\n"
		record, oss, ui = tierFixture(t, []tierCommit{{"oss", "deployment/docker-compose.yml", scalar}},
			[]tierCommit{{"oss", "deployment/docker-compose.yml", strings.Replace(scalar, "{\"a\": 1}\n", "{\"a\": 1}\n      # inside the scalar\n", 1)}}, true)
		if line, code := decideFromRecord(record, oss, ui); code != ExitRequired || !strings.Contains(line, "tier full") {
			t.Errorf("a # line inside a block scalar was judged a comment: exit %d: %s", code, line)
		}

		// A quick record is never an e2e-full mint.
		quickAsFull, oss2, ui2 := tierFixture(t, nil, nil, false)
		text, err := os.ReadFile(quickAsFull)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(quickAsFull, []byte(strings.Replace(string(text), "make e2e-full", "make e2e-quick", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if line, code := decideFromRecord(quickAsFull, oss2, ui2); code != ExitRequired {
			t.Errorf("an e2e-quick record read as the e2e-full record satisfied the mint: exit %d: %s", code, line)
		}
	})
}

// tierCommit is one file committed in a tier fixture: repo "oss" or "ui".
type tierCommit struct{ repo, path, content string }

// tierFixture builds this repository and its sibling, commits base, writes a
// green e2e-full record pinned to both heads, commits change, and — when quick
// — writes a green e2e-quick record pinned to the CURRENT heads beside it.
func tierFixture(t *testing.T, base, change []tierCommit, quick bool) (record, oss, ui string) {
	t.Helper()
	oss, _ = newTree(t)
	ui, _ = newTree(t)
	dir := func(r string) string {
		if r == "ui" {
			return ui
		}
		return oss
	}
	commit := func(c tierCommit) {
		full := filepath.Join(dir(c.repo), c.path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		gitIn(t, dir(c.repo), "add", c.path)
		gitIn(t, dir(c.repo), "commit", "-q", "-m", "change "+c.path)
	}
	for _, c := range base {
		commit(c)
	}
	heads := func() (string, string) {
		return gitIn(t, ui, "rev-parse", "--short", "HEAD"), gitIn(t, oss, "rev-parse", "--short", "HEAD")
	}
	recDir := t.TempDir()
	record = filepath.Join(recDir, "GATE-RUN.e2e-full.txt")
	uiHead, ossHead := heads()
	writeRecordNamed(t, record, "e2e-full", uiHead, ossHead)
	for _, c := range change {
		commit(c)
	}
	if quick {
		uiHead, ossHead = heads()
		writeRecordNamed(t, filepath.Join(recDir, "GATE-RUN.e2e-quick.txt"), "e2e-quick", uiHead, ossHead)
	}
	return record, oss, ui
}

// writeRecordNamed writes a green, finished gate-run.v1 record for mode
// ("e2e-full" or "e2e-quick") at p.
func writeRecordNamed(t *testing.T, p, mode, uiHead, ossHead string) {
	t.Helper()
	text := "schema: gate-run.v1\ngate: identuum-ui make " + mode + "\nrepo-head: " + uiHead +
		"\nplan: a\ntarget: a exit=0\nfinished: 2026-09-26T10:00:00Z\n" +
		"xrepo: identuum-idp-oss head=" + ossHead + " tree=sha256:3729e7ca\nresult: green\n"
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
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
