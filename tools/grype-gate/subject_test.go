package main

// THE-JUDGE-AND-ITS-SUBJECT / GRYPE-SUBJECT-1. The judge names the subject a
// report judged and evaluates only the predicates that subject admits: an
// IMAGE admits neither the applied-configuration predicate (a) nor the
// exclude-coverage predicate (b) — both are reported NOT APPLICABLE on the
// evidence line, never passed silently, never counted as failures, and the
// vulnerability verdict stays the gate — while a DIRECTORY keeps both
// predicates with their full teeth, evaluated against the SUBJECT'S own
// tree, and a -root that is not the subject is refused. Everything below is
// fixture-driven through run(): no scanner is invoked. Measured before this
// slice: identuum-ui's image scan, driven from this checkout with
// `go run -C`, was compared with THIS repository's .grype.yaml (red since
// e12bd79) and this repository's gitignored executables were enumerated as
// the image's coverage — a pass about the wrong tree.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const imageSource = `{"type":"image","target":{"userInput":"identuum-ui:verify","imageID":"sha256:034e","tags":["identuum-ui:verify"]}}`

func dirSource(target string) string { return fmt.Sprintf(`{"type":"directory","target":%q}`, target) }

// appliedConfig is the descriptor.configuration grype records when the
// fixture declaration below was applied to root (excludes as absolute paths,
// the db age in nanoseconds, the ignore by id).
func appliedConfig(root string) string {
	return fmt.Sprintf(`{"exclude":[%q],"db":{"validate-age":true,"max-allowed-built-age":432000000000000},"ignore":[{"vulnerability":"GO-2026-5932"}]}`,
		filepath.Join(root, "bin/**"))
}

const unappliedConfig = `{"exclude":[],"db":{"validate-age":true,"max-allowed-built-age":432000000000000},"ignore":[]}`

func report(source, config string, matches ...string) []byte {
	return []byte(`{"matches":[` + strings.Join(matches, ",") + `],"source":` + source + `,"descriptor":{"configuration":` + config + `}}`)
}

func writeScan(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// subjectRepo is a DIRECTORY subject: a git work tree with the fixture
// declaration, a gitignored excluded executable under bin/, and optionally a
// gitignored executable the declaration does not cover.
func subjectRepo(t *testing.T, withStray bool) string {
	t.Helper()
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v (%s)", err, out)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, ".grype.yaml"), []byte("exclude:\n  - ./bin/**\ndb:\n  validate-age: true\n  max-allowed-built-age: 120h\nignore:\n  - vulnerability: GO-2026-5932\n"), 0o600))
	must(os.WriteFile(filepath.Join(root, ".gitignore"), []byte("bin/\nstray\n"), 0o600))
	must(os.MkdirAll(filepath.Join(root, "bin"), 0o755))
	must(os.WriteFile(filepath.Join(root, "bin", "tool"), []byte("#!/bin/sh\n"), 0o755))
	if withStray {
		must(os.WriteFile(filepath.Join(root, "stray"), []byte("#!/bin/sh\n"), 0o755))
	}
	return root
}

func judge(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out, &out)
	line := strings.TrimSpace(out.String())
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("the judge must print exactly one line, got:\n%s", line)
	}
	return code, line
}

// RULE: GRYPE-SUBJECT-1
func TestRule_GRYPE_SUBJECT_1(t *testing.T) {
	noAllowlist := filepath.Join(t.TempDir(), "absent-allowlist.json")
	// A root WITHOUT a declaration: any attempt to read it is exit 2, so an
	// image subject judged green against it proves the predicates were not
	// consulted rather than quietly passed.
	bareRoot := t.TempDir()

	t.Run("image: verdict is the gate, both predicates not applicable and SAID so", func(t *testing.T) {
		scan := writeScan(t, report(imageSource, unappliedConfig, unfixable("GO-2026-5932", "golang.org/x/crypto", "v0.56.0", "Low")))
		code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist, "-root", bareRoot)
		if code != 0 {
			t.Fatalf("an image with one unfixable Low finding must pass; exit %d: %s", code, line)
		}
		for _, want := range []string{"check OK: grype-gate", "subject image:identuum-ui:verify", "config: not applicable", "coverage: not applicable"} {
			if !strings.Contains(line, want) {
				t.Errorf("evidence line must carry %q; got %q", want, line)
			}
		}
		if strings.Contains(line, "config applied") || strings.Contains(line, "all excluded") {
			t.Errorf("an image subject must not report a directory predicate as passed; got %q", line)
		}
	})
	t.Run("image: a fixable finding still fails", func(t *testing.T) {
		scan := writeScan(t, report(imageSource, unappliedConfig, fixable("GO-2026-6354", "golang.org/x/crypto", "v0.55.0", "High", "0.56.0")))
		code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist, "-root", bareRoot)
		if code != 1 || !strings.HasPrefix(line, "check FAILED: grype-gate") {
			t.Fatalf("the vulnerability verdict must remain the gate for an image; exit %d: %s", code, line)
		}
	})
	t.Run("image: -coverage-only has no tree to judge", func(t *testing.T) {
		scan := writeScan(t, report(imageSource, unappliedConfig))
		if code, line := judge(t, "-scan", scan, "-coverage-only", "-root", bareRoot); code != 2 || !strings.Contains(line, "CANNOT-EVALUATE") {
			t.Fatalf("coverage-only on an image must be cannot-evaluate; exit %d: %s", code, line)
		}
	})

	t.Run("directory: both predicates keep their teeth, evaluated on the subject", func(t *testing.T) {
		root := subjectRepo(t, false)
		scan := writeScan(t, report(dirSource(root), appliedConfig(root), unfixable("GO-2026-5932", "golang.org/x/crypto", "v0.56.0", "Low")))
		// -root deliberately points at a bare directory: the subject's own
		// tree must be read because the report names it, not the caller's.
		code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist)
		if code != 0 {
			t.Fatalf("PREMISE: a covered, applied directory subject must pass; exit %d: %s", code, line)
		}
		for _, want := range []string{"subject directory:" + root, "config applied (1 exclude(s), db max-allowed-built-age 120h, 1 declared ignore(s))", "coverage: 1 gitignored executable(s), all excluded (./bin/**)"} {
			if !strings.Contains(line, want) {
				t.Errorf("evidence line must carry %q; got %q", want, line)
			}
		}
		// (b) red: a gitignored executable the declaration does not cover.
		strayRoot := subjectRepo(t, true)
		scan = writeScan(t, report(dirSource(strayRoot), appliedConfig(strayRoot)))
		code, line = judge(t, "-scan", scan, "-allowlist", noAllowlist)
		if code != 1 || !strings.HasPrefix(line, "check FAILED: grype-gate coverage:") || !strings.Contains(line, "stray") {
			t.Fatalf("an uncovered gitignored executable must fail coverage naming it; exit %d: %s", code, line)
		}
		// (a) red: the scanner applied something other than the declaration.
		scan = writeScan(t, report(dirSource(root), unappliedConfig))
		code, line = judge(t, "-scan", scan, "-allowlist", noAllowlist)
		if code != 1 || !strings.HasPrefix(line, "check FAILED: grype-gate config:") || !strings.Contains(line, "declared exclude ./bin/** is not in effect") {
			t.Fatalf("a declaration the scanner did not apply must fail config; exit %d: %s", code, line)
		}
	})
	t.Run("directory: a relative target is the caller's root", func(t *testing.T) {
		root := subjectRepo(t, false)
		scan := writeScan(t, report(dirSource("."), appliedConfig(root)))
		if code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist, "-root", root); code != 0 || !strings.Contains(line, "subject directory:"+root) {
			t.Fatalf("`dir:.` records \".\", which is the caller's root; exit %d: %s", code, line)
		}
	})
	t.Run("directory: a -root that is not the subject is refused", func(t *testing.T) {
		root := subjectRepo(t, false)
		scan := writeScan(t, report(dirSource(root), appliedConfig(root)))
		if code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist, "-root", bareRoot); code != 2 || !strings.Contains(line, "is not the scan's subject") {
			t.Fatalf("the judge must not read the caller's tree for another subject; exit %d: %s", code, line)
		}
	})
	t.Run("unknown subject kind is cannot-evaluate", func(t *testing.T) {
		scan := writeScan(t, report(`{"type":"file","target":"/tmp/x"}`, unappliedConfig))
		if code, line := judge(t, "-scan", scan, "-allowlist", noAllowlist); code != 2 || !strings.Contains(line, "neither a directory nor an image") {
			t.Fatalf("an unknown subject must be cannot-evaluate; exit %d: %s", code, line)
		}
	})
}
