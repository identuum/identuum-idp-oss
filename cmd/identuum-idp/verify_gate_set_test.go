package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyGateSetBoundaryContract(t *testing.T) {
	makefile := readGateContractFile(t, "../../Makefile")
	start := strings.Index(makefile, "\nverify:\n")
	end := strings.Index(makefile, "\nci-verify:\n")
	if start < 0 || end <= start {
		t.Fatal("Makefile must carry distinct verify and ci-verify targets")
	}
	verify := makefile[start:end]

	build := "gograph build . --precise"
	boundary := "gograph boundaries --config boundaries.json"
	if strings.Count(verify, boundary) != 1 {
		t.Fatalf("the full idp-oss verify gate must run the boundary check exactly once; count=%d", strings.Count(verify, boundary))
	}
	buildIdx := strings.Index(verify, build)
	if buildIdx < 0 || buildIdx >= strings.Index(verify, boundary) {
		t.Fatal("verify must precisely rebuild the graph before evaluating boundaries.json")
	}

	readme := readGateContractFile(t, "../../README.md")
	for _, required := range []string{
		"The repo-local close gate is `make verify`.",
		"`gograph boundaries --config boundaries.json`",
		"does not execute DB-backed integration tests",
		"does not run the race detector locally",
		"does not execute gograph or the boundary policy",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README validation matrix must state %q", required)
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list cmd Go files: %v", err)
	}
	const testSupportImport = `"github.com/identuum/identuum-idp-oss/internal/testsupport"`
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		if strings.Contains(readGateContractFile(t, file), testSupportImport) {
			t.Fatalf("internal/testsupport boundary permission is test-only, but production file %s imports it", file)
		}
	}
}

func readGateContractFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
