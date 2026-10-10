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
