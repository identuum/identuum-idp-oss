package main

// THE-ONE-MINT-RECORD / MINT-RECORD-AUTHORITY-1. The mint decision reads ONE
// authority — the record the mint itself produces — and answers from it:
// a green, finished record whose two heads are in the judged trees' histories
// SATISFIES the question when every path changed since is declared no-reach;
// an ABSENT record, a RED record, and a record pinning a head that is not in
// the judged tree each fail to satisfy it. Everything here is hermetic: two
// throwaway git repositories stand in for this repository and its sibling, the
// record is a fixture file, and no mint is run.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.test",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v (%s)", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// newTree makes a repository with one committed file and returns its root and
// the short hash of that first commit — the head a record would pin.
func newTree(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "README.md")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	return dir, gitIn(t, dir, "rev-parse", "--short", "HEAD")
}

// commitPath adds one more committed file under path, so HEAD moves past the
// recorded head by exactly that path.
func commitPath(t *testing.T, dir, path string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", path)
	gitIn(t, dir, "commit", "-q", "-m", "change "+path)
}

func writeRecord(t *testing.T, result, uiHead, ossHead string) string {
	t.Helper()
	text := "schema: gate-run.v1\ngate: identuum-ui make e2e-full\nrepo-head: " + uiHead +
		"\nplan: a\ntarget: a exit=0\nfinished: 2026-09-12T21:55:33Z\n" +
		"xrepo: identuum-idp-oss head=" + ossHead + " tree=sha256:3729e7ca\nresult: " + result + "\n"
	p := filepath.Join(t.TempDir(), "GATE-RUN.e2e-full.txt")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// RULE: MINT-RECORD-AUTHORITY-1
func TestRuleMintRecordAuthority1_OnlyAGreenMatchingRecordSatisfies(t *testing.T) {
	oss, ossHead := newTree(t)
	ui, uiHead := newTree(t)

	t.Run("green record, both heads in history, nothing changed → SATISFIED", func(t *testing.T) {
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, ossHead), oss, ui)
		if code != ExitSkippable || !strings.Contains(line, "MINT SATISFIED by GATE-RUN.e2e-full.txt") {
			t.Fatalf("PREMISE: a green matching record must satisfy; exit %d: %s", code, line)
		}
		for _, want := range []string{"identuum-ui " + uiHead, "identuum-idp-oss " + ossHead, "no change since the last minted witness"} {
			if !strings.Contains(line, want) {
				t.Errorf("the line must name %q; got %q", want, line)
			}
		}
	})
	t.Run("absent record → MINT REQUIRED, never satisfied", func(t *testing.T) {
		line, code := decideFromRecord(filepath.Join(t.TempDir(), "GATE-RUN.e2e-full.txt"), oss, ui)
		if code != ExitRequired || !strings.Contains(line, "MINT REQUIRED") || !strings.Contains(line, "no e2e record at") {
			t.Fatalf("an absent record must require the mint; exit %d: %s", code, line)
		}
		if strings.Contains(line, "SATISFIED") {
			t.Fatalf("an absent record satisfied the question: %s", line)
		}
	})
	t.Run("red record → MINT REQUIRED: a red record is not a mint", func(t *testing.T) {
		line, code := decideFromRecord(writeRecord(t, "red", uiHead, ossHead), oss, ui)
		if code != ExitRequired || !strings.Contains(line, "MINT REQUIRED") || !strings.Contains(line, "a red record is not a mint") {
			t.Fatalf("a red record must require the mint; exit %d: %s", code, line)
		}
	})
	t.Run("sibling head not in the judged tree → MINT REQUIRED: the record vouches for another tree", func(t *testing.T) {
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, "0123456789abcdef0123456789abcdef01234567"), oss, ui)
		if code != ExitRequired || !strings.Contains(line, "MINT REQUIRED") || !strings.Contains(line, "not in the history of the identuum-idp-oss tree being judged") {
			t.Fatalf("a head outside the judged tree must require the mint; exit %d: %s", code, line)
		}
	})
	t.Run("green record, a reaching path changed since → MINT REQUIRED by the unchanged reachability rule", func(t *testing.T) {
		oss2, ossHead2 := newTree(t)
		commitPath(t, oss2, "internal/handlers/x.go")
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, ossHead2), oss2, ui)
		if code != ExitRequired || !strings.Contains(line, "1 of 1 changed path(s) reach the appliance: internal/handlers/x.go") {
			t.Fatalf("a reaching change since the record must require the mint; exit %d: %s", code, line)
		}
	})
	t.Run("green record, only a no-reach path changed since → SATISFIED, the path justified by name", func(t *testing.T) {
		oss3, ossHead3 := newTree(t)
		commitPath(t, oss3, "docs/notes.md")
		line, code := decideFromRecord(writeRecord(t, "green", uiHead, ossHead3), oss3, ui)
		if code != ExitSkippable || !strings.Contains(line, "MINT SATISFIED") || !strings.Contains(line, "docs/notes.md [") {
			t.Fatalf("a no-reach change since the record must still satisfy, naming the path; exit %d: %s", code, line)
		}
	})
}
