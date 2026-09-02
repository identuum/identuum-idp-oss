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

	// THE-LEDGER-DIFF-GATE: the ledger-diff reconciliation runs in the full
	// verify plan exactly once, right after rulefloor-check (both cheap; both
	// fail the aggregate before the expensive gates).
	const ledgerCheck = "'rulefloor-check=$(MAKE) --no-print-directory rulefloor-check'"
	const ledgerDiff = "'ledger-diff-gate=$(MAKE) --no-print-directory ledger-diff-gate'"
	if strings.Count(verify, ledgerDiff) != 1 {
		t.Fatalf("the full idp-oss verify gate must run ledger-diff-gate exactly once; count=%d", strings.Count(verify, ledgerDiff))
	}
	if ci, ld := strings.Index(verify, ledgerCheck), strings.Index(verify, ledgerDiff); ci < 0 || ld < ci {
		t.Fatal("verify must run rulefloor-check before ledger-diff-gate")
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
