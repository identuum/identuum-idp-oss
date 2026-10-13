package main

import (
	"os"
	"strings"
	"testing"
)

// THE-UNRUN-SUITE. The integration-tagged suites had no gate: `make verify`
// type-checks them and runs nothing, so a profile that stopped running, or ran
// red, changed no visible fact. Two defects reached a witness through that
// gap.
//
// This rule pins the gate that closes it: the verdict has three outcomes and
// no fourth, a vacuous run is NOT green, a missing database is exit 2 and
// never a pass, and the wiring that makes the profile run at all — the
// entry point, its record, and its place in the two-repo mint — is present.

// RULE: INTEGRATION-GATE-1
func TestRule_INTEGRATION_GATE_1(t *testing.T) {
	// ── (1) The verdict table. Each case is a shape the runner really
	// produces; the fixtures are trimmed transcripts, not invented text.
	cases := []struct {
		name      string
		output    string
		runFailed bool
		want      Verdict
		wantExit  int
		wantLine  string
	}{
		{
			name: "a green profile",
			output: "=== RUN   TestA\n--- PASS: TestA (0.01s)\n" +
				"=== RUN   TestB\n=== RUN   TestB/sub\n--- PASS: TestB (0.00s)\n    --- PASS: TestB/sub (0.00s)\n" +
				"ok  \tgithub.com/identuum/identuum-idp-oss/internal/postgres\t1.119s\n",
			want:     VerdictGreen,
			wantExit: 0,
			wantLine: "check OK: integration-profile packages=1 passed=3 skipped=0 failed=0",
		},
		{
			name: "a failing test",
			output: "--- PASS: TestA (0.01s)\n--- FAIL: TestB (0.02s)\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/e2e\t6.592s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "check FAILED: integration-profile packages=1 passed=1 skipped=0 failed=1",
		},
		{
			name:     "THE VACUOUS RUN: nothing executed",
			output:   "?   \tgithub.com/identuum/identuum-idp-oss/tools/x\t[no test files]\n",
			want:     VerdictRed,
			wantExit: 1,
			wantLine: "check FAILED: integration-profile ran NO tests",
		},
		{
			name:     "a vacuous run that exited 0 is still not green",
			output:   "",
			want:     VerdictRed,
			wantExit: 1,
			wantLine: "ran NO tests",
		},
		{
			name: "no database: the harness's own fatal",
			output: "--- FAIL: TestBundleAtomic_HappyPathCreatesBoundPair (0.00s)\n" +
				"    service_account_client_bundle_pgx_test.go:97: IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/e2e\t0.719s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name: "no database: nothing listening",
			output: "--- FAIL: TestX (0.00s)\n    open pool: failed to connect to `user=idp_oss_user database=x`: " +
				"127.0.0.1:5513 (127.0.0.1): dial error: connection refused\nFAIL\tpkg\t0.1s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name:      "no database: the database does not exist",
			output:    "--- FAIL: TestY (0.00s)\n    ERROR: database \"identuum_idp_oss_test\" does not exist (SQLSTATE 3D000)\nFAIL\tpkg\t0.1s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name:      "a build failure is red, not 'nothing ran'",
			output:    "# github.com/identuum/identuum-idp-oss/internal/e2e\n./x_test.go:12:2: undefined: Foo\nFAIL\tpkg [build failed]\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "did not build",
		},
		{
			name: "a real database failure with tests passing around it stays RED",
			output: "--- PASS: TestA (0.01s)\n--- FAIL: TestB (0.02s)\n    x_test.go:9: expected 404, got 503\n" +
				"FAIL\tpkg\t1.0s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "failed=1",
		},
		// THE-HIDDEN-RED (OSS-INTEGRATION-WITNESS-FIX). Only the failed
		// tests' own lines can explain a failure: the redis and SMTP suites
		// log "connection refused" by design while they PASS, and a real
		// failure beside them was once read as "no database".
		{
			name: "a real failure beside a passing test's connection-refused log stays RED",
			output: "=== RUN   TestRedisClient\n" +
				"redis: 2026/10/12 19:30:58 pool.go:762: redis: connection pool: failed to dial after 5 attempts: dial tcp 127.0.0.1:57346: connect: connection refused\n" +
				"--- PASS: TestRedisClient (3.10s)\nPASS\n" +
				"ok  \tgithub.com/identuum/identuum-idp-oss/internal/infra/cache\t3.2s\n" +
				"=== RUN   TestB\n    x_test.go:9: expected 404, got 503\n--- FAIL: TestB (0.02s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/e2e\t1.0s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "failed=1 first=github.com/identuum/identuum-idp-oss/internal/e2e.TestB",
		},
		{
			name: "every failed test shows the pgx connect error to the DSN: CANNOT-EVALUATE",
			output: "=== RUN   TestX\n    x_test.go:12: open pool: failed to connect to `user=idp_oss_user database=identuum_idp_oss_test`: " +
				"127.0.0.1:5513 (127.0.0.1): dial error: connection refused\n--- FAIL: TestX (0.00s)\n" +
				"=== RUN   TestY\n    y_test.go:30: failed to connect to `user=idp_oss_user database=identuum_idp_oss_test`: " +
				"127.0.0.1:5513 (localhost): server error: FATAL: the database system is starting up (SQLSTATE 57P03)\n--- FAIL: TestY (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/postgres\t0.3s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name: "mixed database and non-database failures stay RED",
			output: "=== RUN   TestX\n    x_test.go:12: open pool: failed to connect to `user=idp_oss_user database=identuum_idp_oss_test`: " +
				"127.0.0.1:5513 (127.0.0.1): dial error: connection refused\n--- FAIL: TestX (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/postgres\t0.3s\n" +
				"=== RUN   TestToken\n    token_test.go:401: expected 200, got 500: dial tcp 127.0.0.1:1: connect: connection refused\n" +
				"--- FAIL: TestToken (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/handlers\t0.2s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "failed=2 first=github.com/identuum/identuum-idp-oss/internal/handlers.TestToken failed_packages=github.com/identuum/identuum-idp-oss/internal/postgres,github.com/identuum/identuum-idp-oss/internal/handlers",
		},
		{
			name: "a pgx connect error to a server that is not the DSN's stays RED",
			output: "=== RUN   TestDialer\n    dialer_test.go:7: failed to connect to `user=u database=d`: 127.0.0.1:1 (127.0.0.1): dial error: connection refused\n" +
				"--- FAIL: TestDialer (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/infra\t0.1s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/internal/infra.TestDialer",
		},
		{
			name: "a parent failed only by its database-failed subtest is explained by it",
			output: "=== RUN   TestRepo\n=== RUN   TestRepo/create\n" +
				"    repo_test.go:20: failed to connect to `user=idp_oss_user database=identuum_idp_oss_test`: 127.0.0.1:5513 (127.0.0.1): dial error: connection refused\n" +
				"--- FAIL: TestRepo (0.00s)\n    --- FAIL: TestRepo/create (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/postgres\t0.1s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name: "a parent's own non-database error is not hidden by a database-failed subtest",
			output: "=== RUN   TestRepo\n=== RUN   TestRepo/create\n" +
				"    repo_test.go:20: failed to connect to `user=idp_oss_user database=identuum_idp_oss_test`: 127.0.0.1:5513 (127.0.0.1): dial error: connection refused\n" +
				"=== NAME  TestRepo\n    repo_test.go:31: cleanup left 3 rows\n" +
				"--- FAIL: TestRepo (0.00s)\n    --- FAIL: TestRepo/create (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/postgres\t0.1s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/internal/postgres.TestRepo ",
		},
		{
			name: "a package that fails before any test, on the harness's missing-DSN fatal: CANNOT-EVALUATE",
			output: "IDENTUUM_IDP_TEST_DATABASE_URL is not set; the provisioning teeth were requested via -tags integration\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/runtime\t0.1s\n",
			runFailed: true,
			want:      VerdictCannotEvaluate,
			wantExit:  2,
			wantLine:  "CANNOT-EVALUATE",
		},
		{
			name: "a package that fails before any test for another reason stays RED and is named",
			output: "--- PASS: TestA (0.01s)\nok  \tgithub.com/identuum/identuum-idp-oss/internal/a\t0.1s\n" +
				"panic: init: dial tcp 127.0.0.1:6379: connect: connection refused\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/internal/b\t0.1s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/internal/b failed_packages=github.com/identuum/identuum-idp-oss/internal/b",
		},
		// OSS-INTEGRATION-WITNESS-FIX-REVIEW F1-F4. Trimmed from real
		// go1.27.2 `go test -v -p 1` output of the reviewer's probes.
		{
			name: "F1: a goroutine panic is red even when a PASSING test logged a database error",
			output: "=== RUN   TestPassLogsDB\n" +
				"    b_test.go:13: failed to connect to `user=u database=d_test`: 127.0.0.1:5513 (127.0.0.1): dial error: connect: connection refused\n" +
				"--- PASS: TestPassLogsDB (0.00s)\n=== RUN   TestGoroutinePanic\npanic: nil map write in worker\n\ngoroutine 21 [running]:\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/zzprobe/b\t0.265s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/zzprobe/b ",
		},
		{
			name: "F1: a timeout is red even when a PASSING test logged SQLSTATE 3D000",
			output: "=== RUN   TestWrongDBRefused\n" +
				"    e_test.go:13: got expected error: FATAL: database \"nope_test\" does not exist (SQLSTATE 3D000)\n" +
				"--- PASS: TestWrongDBRefused (0.00s)\n=== RUN   TestHang\npanic: test timed out after 2s\n" +
				"testing.tRunner(0x1953881c8488, 0x1022e3730)\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/zzprobe/e\t2.167s\nFAIL\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/zzprobe/e ",
		},
		{
			name: "F2: a parent's panic after a database-failed subtest is red",
			output: "=== RUN   TestParentPanicAfterDBSub\n=== RUN   TestParentPanicAfterDBSub/db\n" +
				"    c_test.go:11: failed to connect to `user=u database=d_test`: 127.0.0.1:5513 (127.0.0.1): dial error: connect: connection refused\n" +
				"--- FAIL: TestParentPanicAfterDBSub (0.00s)\n    --- FAIL: TestParentPanicAfterDBSub/db (0.00s)\n" +
				"panic: nil map write in parent [recovered, repanicked]\n\ngoroutine 5 [running]:\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/zzprobe/c\t0.230s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/zzprobe/c.TestParentPanicAfterDBSub ",
		},
		{
			name: "F3: a background goroutine's untagged database line is not the failing test's",
			output: "=== RUN   TestBgLogger\n--- PASS: TestBgLogger (0.00s)\n=== RUN   TestRealAfter\n" +
				"pool: failed to connect to `user=u database=d_test`: 127.0.0.1:5513 (127.0.0.1): dial error: connect: connection refused\n" +
				"    d_test.go:24: expected 404, got 500\n--- FAIL: TestRealAfter (0.06s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/zzprobe/d\t0.236s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "first=github.com/identuum/identuum-idp-oss/zzprobe/d.TestRealAfter ",
		},
		{
			name: "F4: a --- FAIL inside a multi-line t.Log is not a failure",
			output: "=== RUN   TestGhost\n    d_test.go:28: child output:\n        --- FAIL: TestGhostChild (0.00s)\n" +
				"--- PASS: TestGhost (0.00s)\n=== RUN   TestReal\n    d_test.go:40: expected 1, got 2\n--- FAIL: TestReal (0.00s)\nFAIL\n" +
				"FAIL\tgithub.com/identuum/identuum-idp-oss/zzprobe/d\t0.236s\n",
			runFailed: true,
			want:      VerdictRed,
			wantExit:  1,
			wantLine:  "passed=1 skipped=0 failed=1 first=github.com/identuum/identuum-idp-oss/zzprobe/d.TestReal ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, counts, line := Classify(tc.output, tc.runFailed, "127.0.0.1:5513")
			if got != tc.want {
				t.Fatalf("verdict = %v, want %v (counts %+v, line %q)", got, tc.want, counts, line)
			}
			if got.ExitCode() != tc.wantExit {
				t.Errorf("exit = %d, want %d", got.ExitCode(), tc.wantExit)
			}
			if !strings.Contains(line, tc.wantLine) {
				t.Errorf("line = %q, want it to contain %q", line, tc.wantLine)
			}
		})
	}

	// ── (2) The three outcomes carry three DISTINCT exit codes, and only
	// green is zero. A gate that cannot run must not be mistaken for one
	// that passed.
	if VerdictGreen.ExitCode() != 0 || VerdictRed.ExitCode() != 1 || VerdictCannotEvaluate.ExitCode() != 2 {
		t.Errorf("exit codes must be green=0 red=1 cannot-evaluate=2; got %d/%d/%d",
			VerdictGreen.ExitCode(), VerdictRed.ExitCode(), VerdictCannotEvaluate.ExitCode())
	}
	// The ZERO value of Verdict must be a failing one: a classifier that
	// returns early cannot read as success.
	var zero Verdict
	if zero.ExitCode() == 0 {
		t.Errorf("the zero Verdict must not exit 0")
	}

	// ── (3) The WIRING. A verdict nobody runs is not a gate.
	makefile := readRepoFile(t, "../../Makefile")

	if !strings.Contains(makefile, "verify-integration:") {
		t.Errorf("the Makefile must define verify-integration — the profile's own entry point (P-041)")
	}
	if !strings.Contains(makefile, "GATE-RUN.integration.txt") {
		t.Errorf("verify-integration must write its own gate-witness record, GATE-RUN.integration.txt")
	}
	for _, planned := range []string{"integration-preflight", "integration-profile", "rulefloor-integration"} {
		if !strings.Contains(makefile, planned) {
			t.Errorf("verify-integration must drive the %q target through the record", planned)
		}
	}
	// The witness must be BUILT and executed, never `go run`: MEASURED —
	// `go run` reports a child's exit 2 as its own exit 1, which would
	// collapse CANNOT-EVALUATE into an ordinary failure and lose the very
	// distinction this gate promises.
	gate := section(makefile, "verify-integration:")
	if strings.Contains(gate, "go run ./tools/integration-witness") {
		t.Errorf("verify-integration must run the BUILT witness (go run collapses exit 2 into 1); got:\n%s", gate)
	}
	if !strings.Contains(gate, "./bin/integration-witness") {
		t.Errorf("verify-integration must execute ./bin/integration-witness; got:\n%s", gate)
	}
	// It runs in the two-repo mint, where a database already stands up —
	// and the mint re-checks the record it left.
	//
	// THE-UNMINTED-DIFF: the mint is now reached through a DISPATCH.
	// `test-full` asks tools/mint-reachability whether the diff can reach
	// the appliance and delegates to `test-full-mint`, so the body this
	// invariant is about moved one target along. Both halves are asserted —
	// that test-full still delegates, and that the delegate still does the
	// work — because checking only the delegate would let the dispatch be
	// deleted, and checking only the dispatch would let the body rot.
	entry := section(makefile, "test-full:")
	if !strings.Contains(entry, "test-full-mint") {
		t.Errorf("test-full must dispatch to test-full-mint; got:\n%s", entry)
	}
	if !strings.Contains(entry, "mint-reachability") {
		t.Errorf("test-full must consult the reachability classifier before skipping the mint; got:\n%s", entry)
	}
	mint := section(makefile, "test-full-mint:")
	if !strings.Contains(mint, "verify-integration") {
		t.Errorf("test-full-mint (the two-repo mint) must run verify-integration; got:\n%s", mint)
	}
	if !strings.Contains(mint, "GATE-RUN.integration.txt") {
		t.Errorf("test-full-mint must re-check the integration record, as it does the e2e-full one; got:\n%s", mint)
	}
	// `make verify` stays DATABASE-FREE (the ruling's whole point): it must
	// not gain the profile.
	verify := section(makefile, "verify:")
	if strings.Contains(verify, "verify-integration") || strings.Contains(verify, "ci-integration-test") {
		t.Errorf("make verify must stay database-free (P-041); got:\n%s", verify)
	}

	// The record is gitignored for the same reason the e2e-full one is: a
	// second committed record would stale the first one's tree digest.
	ignore := readRepoFile(t, "../../.gitignore")
	if !strings.Contains(ignore, "/GATE-RUN.integration.txt") {
		t.Errorf(".gitignore must carry /GATE-RUN.integration.txt, like /GATE-RUN.e2e-full.txt in the ui")
	}
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// section returns the make target block starting at name, up to the next
// line that begins in column 0 and is not part of the recipe.
func section(makefile, name string) string {
	i := strings.Index(makefile, "\n"+name)
	if i < 0 {
		return ""
	}
	rest := makefile[i+1:]
	lines := strings.Split(rest, "\n")
	out := []string{lines[0]}
	for _, l := range lines[1:] {
		if l == "" || strings.HasPrefix(l, "\t") || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "#") {
			out = append(out, l)
			continue
		}
		break
	}
	recipe := strings.Join(out, "\n")
	// Follow extracted argument vectors; all wiring assertions still inspect
	// the commands the selected recipe actually passes to its driver.
	for _, definition := range strings.Split(makefile, "\ndefine ")[1:] {
		declaration, _, closed := strings.Cut(definition, "\nendef")
		variable, body, named := strings.Cut(declaration, "\n")
		if closed && named {
			recipe = strings.ReplaceAll(recipe, "$("+variable+")", body)
		}
	}
	return recipe
}
