package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const liteLedger = `FLOOR: 2

| ID | one-sentence rule | enforced-by | check | red-proof | hash |
|---|---|---|---|---|---|
| L-1 | Spec rule. | playwright | e2e/a.spec.ts @ chromium | - | abcdef012345 |
| L-2 | Go rule. | go-test | a_test.go @ unit | - | abcdef012345 |
`

func liteRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("RULE-FLOOR.md", liteLedger)
	write("e2e/a.spec.ts", "test('holds [L-1]', async () => {});\n")
	write("a_test.go", "package a\n\n// RULE: L-2\nfunc TestL2(t *testing.T) {}\n")
	return repo
}

func mustProblems(t *testing.T, repo string) []string {
	t.Helper()
	problems, err := liteCheck(repo)
	if err != nil {
		t.Fatalf("liteCheck: %v", err)
	}
	return problems
}

func TestLite_CleanRepoPasses(t *testing.T) {
	if p := mustProblems(t, liteRepo(t)); len(p) != 0 {
		t.Fatalf("clean repo reported problems: %v", p)
	}
}

// Every failure mode the subset promises, red-proved.
func TestLite_FailureModes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, repo string)
		want   string
	}{
		{"deleted row drops below FLOOR", func(t *testing.T, repo string) {
			p := filepath.Join(repo, "RULE-FLOOR.md")
			data, _ := os.ReadFile(p)
			out := strings.Replace(string(data), "| L-2 | Go rule. | go-test | a_test.go @ unit | - | abcdef012345 |\n", "", 1)
			os.WriteFile(p, []byte(out), 0o644)
		}, "below FLOOR"},
		{"check file missing", func(t *testing.T, repo string) {
			os.Remove(filepath.Join(repo, "e2e/a.spec.ts"))
		}, "check file missing"},
		{"spec tag absent", func(t *testing.T, repo string) {
			os.WriteFile(filepath.Join(repo, "e2e/a.spec.ts"), []byte("test('untagged', async () => {});\n"), 0o644)
		}, "absent from"},
		{"go tag absent", func(t *testing.T, repo string) {
			os.WriteFile(filepath.Join(repo, "a_test.go"), []byte("package a\n\nfunc TestL2(t *testing.T) {}\n"), 0o644)
		}, "absent from"},
		{"tagged title line gains .skip", func(t *testing.T, repo string) {
			os.WriteFile(filepath.Join(repo, "e2e/a.spec.ts"), []byte("test.skip('holds [L-1]', async () => {});\n"), 0o644)
		}, ".skip/.only"},
		{"tagged title line gains .only", func(t *testing.T, repo string) {
			os.WriteFile(filepath.Join(repo, "e2e/a.spec.ts"), []byte("test.only('holds [L-1]', async () => {});\n"), 0o644)
		}, ".skip/.only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := liteRepo(t)
			tc.mutate(t, repo)
			problems := mustProblems(t, repo)
			joined := strings.Join(problems, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("problems %v missing %q", problems, tc.want)
			}
		})
	}
}

func TestLite_MalformedLedgerIsFatal(t *testing.T) {
	repo := liteRepo(t)
	os.WriteFile(filepath.Join(repo, "RULE-FLOOR.md"), []byte("not a ledger\n"), 0o644)
	if _, err := liteCheck(repo); err == nil {
		t.Fatal("malformed ledger must be a parse fault, not a pass")
	}
}
