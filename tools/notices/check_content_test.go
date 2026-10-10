package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withoutSubpackageTexts is the incomplete-probe specimen of review
// OSS-FIXES-3 F3: the notices file with every Go licence text that lives below
// a module's root (crypto/secp256k1/LICENSE, revoke/LICENSE and
// internal/github.com/golang/gddo/LICENSE when the review ran) cut out, while
// every component header and both fingerprint lines stay.
func withoutSubpackageTexts(t *testing.T, file string) (string, int) {
	t.Helper()
	sep := strings.Repeat("=", 78)
	var out []string
	cut, eco, skipping := 0, "", false
	for l := range strings.SplitSeq(file, "\n") {
		if l == sep {
			skipping = false
		}
		if strings.HasPrefix(l, "go ") || strings.HasPrefix(l, "npm ") {
			eco = l[:strings.Index(l, " ")]
		}
		if label, ok := strings.CutPrefix(l, "--- "); ok {
			skipping = eco == "go" && strings.Contains(label, "/")
			if skipping {
				cut++
			}
		}
		if !skipping {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n"), cut
}

// The check judges the Go licence texts by regenerating them, not by the
// build-list fingerprint alone: a compiled package's licence file can appear
// or change inside a module already listed, which moves no fingerprint.
func TestCheckRegeneratesGoLicenceTexts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	in, dirs, err := inputs(root)
	if err != nil {
		t.Fatalf("inputs: %v", err)
	}
	committed := filepath.Join(root, "THIRD_PARTY_NOTICES")
	if line, ok := checkFile(committed, in, dirs); !ok {
		t.Fatalf("control: the committed notices file must pass the check; got %q", line)
	}
	raw, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	probe, cut := withoutSubpackageTexts(t, string(raw))
	if cut == 0 {
		t.Fatal("the specimen cut no subpackage licence text; it would prove nothing")
	}
	path := filepath.Join(t.TempDir(), "THIRD_PARTY_NOTICES.incomplete-probe")
	if err := os.WriteFile(path, []byte(probe), 0o600); err != nil {
		t.Fatal(err)
	}
	line, ok := checkFile(path, in, dirs)
	if ok {
		t.Fatalf("a notices file missing %d Go licence text(s) with unchanged fingerprints must FAIL the check; got %q", cut, line)
	}
	if !strings.Contains(line, "Go licence texts") {
		t.Errorf("the refusal must name the Go licence texts; got %q", line)
	}
}

// withoutNPMBody is the npm-omitted specimen of review OSS-MINT-GUARD-2 G3:
// every input header, the complete Go section and the first npm block's
// boundary and header line stay, and every npm licence text and every later
// npm block is cut.
func withoutNPMBody(t *testing.T, file string) string {
	t.Helper()
	sep := "\n\n" + strings.Repeat("=", 78) + "\n"
	start := strings.Index(file, sep+"npm ")
	if start < 0 {
		t.Fatal("the committed notices file has no npm block; the specimen would prove nothing")
	}
	header := start + len(sep)
	end := strings.Index(file[header:], "\n")
	if end < 0 || header+end+1 >= len(file) {
		t.Fatal("the first npm block has nothing after its header line to cut")
	}
	return file[:header+end+1]
}

// The check judges the COMPLETE file, npm half included (review
// OSS-MINT-GUARD-2 G3): an npm body that loses its licence texts or blocks
// while both fingerprints and the Go section stay is refused.
func TestCheckBindsTheCompleteNPMBody(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	in, dirs, err := inputs(root)
	if err != nil {
		t.Fatalf("inputs: %v", err)
	}
	committed := filepath.Join(root, "THIRD_PARTY_NOTICES")
	if line, ok := checkFile(committed, in, dirs); !ok {
		t.Fatalf("control: the committed notices file must pass the check; got %q", line)
	}
	raw, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	probe := withoutNPMBody(t, string(raw))
	if goSection(probe) != goSection(string(raw)) {
		t.Fatal("the specimen changed the Go section; it must isolate the npm omission")
	}
	path := filepath.Join(t.TempDir(), "THIRD_PARTY_NOTICES.npm-omitted")
	if err := os.WriteFile(path, []byte(probe), 0o600); err != nil {
		t.Fatal(err)
	}
	line, ok := checkFile(path, in, dirs)
	if ok {
		t.Fatalf("a notices file whose npm licence texts and later npm blocks are cut, with unchanged fingerprints and Go section, must FAIL the check; got %q", line)
	}
	if !strings.Contains(line, "npm") {
		t.Errorf("the refusal must name the npm body; got %q", line)
	}
	// One changed byte inside an npm licence text is refused too.
	i := strings.LastIndex(string(raw), "Permission")
	if i < 0 || i < strings.Index(string(raw), "\nnpm ") {
		t.Fatal("no npm licence text to alter")
	}
	altered := string(raw[:i]) + "permission" + string(raw[i+len("Permission"):])
	if err := os.WriteFile(path, []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}
	if line, ok := checkFile(path, in, dirs); ok {
		t.Fatalf("one altered byte in an npm licence text must FAIL the check; got %q", line)
	}
}
