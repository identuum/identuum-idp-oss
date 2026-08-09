package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestGeneratedOutputMatchesGoldenFixture pins that the
// annotation-driven generator's YAML output is byte-identical
// to the checked-in `testdata/endpoints.golden.yaml` fixture.
//
// This is the post-P3 verification model. The curated
// `registry.go` fixture stops at 91 endpoints; the live
// annotation set is larger and is allowed to grow whenever
// operators add a new annotated route. The golden fixture
// records the EXACT current expected output and MUST be
// regenerated (by running `go run ./tools/api-docgen --output
// tools/api-docgen/testdata/ && mv tools/api-docgen/testdata/
// endpoints.yaml tools/api-docgen/testdata/endpoints.golden.yaml`)
// any time a route is intentionally added, removed, or
// renamed.
//
// Failure modes the fixture catches that the old parity tests
// did not:
//   - a docgen annotation silently dropped from the source
//     tree (route would still resolve at runtime but stop
//     appearing in the generated catalog).
//   - a docgen annotation reshaped (e.g. summary edited) in a
//     way the operator did not intend.
//   - non-determinism creeping into the extractor.
//
// The fixture is the source of truth for the generator output;
// a delta MUST be reviewed and re-committed before the test
// goes green. No silent fixtures-on-disk updates by the test
// itself — this test deliberately does NOT support an
// `-update` flag.
func TestGeneratedOutputMatchesGoldenFixture(t *testing.T) {
	roots, err := defaultSourceRoots()
	if err != nil {
		t.Fatalf("defaultSourceRoots: %v", err)
	}
	endpoints, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations: %v", err)
	}
	var got bytes.Buffer
	if err := generate(&got, endpoints); err != nil {
		t.Fatalf("generate: %v", err)
	}

	goldenPath := goldenFixturePath(t)
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", goldenPath, err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("generated output diverges from %s — review the diff and, if intentional, re-run:\n  go run ./tools/api-docgen --output tools/api-docgen/testdata/ && mv tools/api-docgen/testdata/endpoints.yaml %s\ngot %d bytes, want %d bytes",
			filepath.Base(goldenPath), filepath.Base(goldenPath), got.Len(), len(want))
	}
}

// TestGeneratedOutputMatchesManifest pins that the (method,
// path) set of the generator's output exactly equals the
// checked-in `testdata/endpoints.manifest.txt` set. The
// manifest is a one-line-per-endpoint plain-text projection
// (format: "METHOD /api/v1/...") that is dramatically easier
// to review in a PR diff than the 56-KB YAML fixture.
//
// Both directions are enforced:
//   - every line in the manifest MUST appear in the generated
//     output (annotation dropped → fail).
//   - every generated (method, path) pair MUST appear in the
//     manifest (annotation added without manifest update →
//     fail).
//
// Regenerate via the recipe printed in the failure message.
func TestGeneratedOutputMatchesManifest(t *testing.T) {
	roots, err := defaultSourceRoots()
	if err != nil {
		t.Fatalf("defaultSourceRoots: %v", err)
	}
	endpoints, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations: %v", err)
	}
	generated := make(map[string]struct{}, len(endpoints))
	for _, e := range endpoints {
		generated[e.Method+" "+e.Path] = struct{}{}
	}

	manifestPath := manifestFixturePath(t)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest fixture %s: %v", manifestPath, err)
	}
	manifest := make(map[string]struct{})
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		manifest[line] = struct{}{}
	}

	var missingFromGenerated, missingFromManifest []string
	for k := range manifest {
		if _, ok := generated[k]; !ok {
			missingFromGenerated = append(missingFromGenerated, k)
		}
	}
	for k := range generated {
		if _, ok := manifest[k]; !ok {
			missingFromManifest = append(missingFromManifest, k)
		}
	}
	sort.Strings(missingFromGenerated)
	sort.Strings(missingFromManifest)

	for _, e := range missingFromGenerated {
		t.Errorf("manifest entry not in generator output — annotation appears to have been dropped: %s", e)
	}
	for _, e := range missingFromManifest {
		t.Errorf("generator output not in manifest — add the line below to %s (sorted insert) or revert the annotation:\n  %s",
			filepath.Base(manifestPath), e)
	}
}

// TestGeneratedOutputCarriesFeatureGateForDCR pins that every DCR
// route surfaces its feature_gate in the YAML output. The 7 DCR routes
// carry `feature_gate: "dynamic_client_registration"`. The count is the
// load-bearing assertion — if a DCR annotation is dropped, the count
// goes down and the test fails.
//
// SCIM (formerly 9 routes with feature_gate "scim") was removed from OSS
// to close a licensing leak — see
// docs/audit/changelog/scim-oss-leak-removal.md. OSS must now carry ZERO
// scim-gated endpoints; that absence is asserted below.
func TestGeneratedOutputCarriesFeatureGateForDCR(t *testing.T) {
	roots, err := defaultSourceRoots()
	if err != nil {
		t.Fatalf("defaultSourceRoots: %v", err)
	}
	endpoints, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations: %v", err)
	}
	counts := map[string]int{}
	dcrPaths := map[string]bool{}
	for _, e := range endpoints {
		if e.FeatureGate == "" {
			continue
		}
		counts[e.FeatureGate]++
		if e.FeatureGate == "dynamic_client_registration" {
			dcrPaths[e.Path] = true
		}
	}
	// Advanced DCR (3 IAT mgmt + 3 RFC 7592 mgmt routes) was removed
	// from the OSS catalog — it was advertised-but-unwired (the runtime
	// never constructed the backing services, so the routes 404'd) and
	// is Enterprise/CE-only. Only basic RFC 7591 POST /oauth/register
	// remains. See docs/audit/changelog/dcr-surface-scoping.md.
	if got := counts["dynamic_client_registration"]; got != 1 {
		t.Errorf("dynamic_client_registration count = %d; want 1 (basic /register only — advanced DCR is CE)", got)
	}
	// SCIM was removed from OSS to close a licensing leak — no
	// scim-gated endpoint must remain in the generated catalog.
	if got := counts["scim"]; got != 0 {
		t.Errorf("scim count = %d; want 0 (SCIM removed from OSS — see scim-oss-leak-removal.md)", got)
	}
	// Pin a representative DCR path so a future rename surfaces here too.
	if !dcrPaths["/api/v1/oauth/register"] {
		t.Errorf("/api/v1/oauth/register missing feature_gate=dynamic_client_registration")
	}
}

// TestGeneratedOutputDeterministicAcrossTwoRuns pins that the
// generator emits byte-identical output across two consecutive
// in-process invocations against the same source tree. This
// is the canonical determinism invariant the P3 extractor was
// designed to uphold.
func TestGeneratedOutputDeterministicAcrossTwoRuns(t *testing.T) {
	roots, err := defaultSourceRoots()
	if err != nil {
		t.Fatalf("defaultSourceRoots: %v", err)
	}
	endpoints1, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations #1: %v", err)
	}
	endpoints2, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations #2: %v", err)
	}
	var a, b bytes.Buffer
	if err := generate(&a, endpoints1); err != nil {
		t.Fatalf("generate #1: %v", err)
	}
	if err := generate(&b, endpoints2); err != nil {
		t.Fatalf("generate #2: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("generator output not deterministic across two runs: %d vs %d bytes", a.Len(), b.Len())
	}
}

// liveEndpoints is the canonical "give me a non-trivial Endpoint
// slice for the tests below" helper. It runs the annotation
// extractor against the default OSS source roots and fails the
// test on extractor error. Use this everywhere the deleted
// `Registry()` fixture used to be the source of truth — the
// extractor is now authoritative.
func liveEndpoints(t *testing.T) []Endpoint {
	t.Helper()
	roots, err := defaultSourceRoots()
	if err != nil {
		t.Fatalf("defaultSourceRoots: %v", err)
	}
	endpoints, err := EndpointsFromAnnotations(roots)
	if err != nil {
		t.Fatalf("EndpointsFromAnnotations: %v", err)
	}
	return endpoints
}

// TestExtractorEmitsMinimumEndpointCount is the defensive floor
// that replaces the deleted Registry-based count tests. The
// extractor's output is otherwise pinned by the golden YAML
// fixture; this test ensures a regression that empties the
// extractor (e.g. wrong source-root resolution) fails loudly
// before the golden comparison would.
func TestExtractorEmitsMinimumEndpointCount(t *testing.T) {
	endpoints := liveEndpoints(t)
	// Conservative floor: the live annotation set has grown
	// past 100 across the foundation + IAT + RFC 7592 + SCIM
	// write slices; 90 is well below today's count but well
	// above any plausible "real" inventory.
	if got := len(endpoints); got < 90 {
		t.Fatalf("extractor returned only %d endpoints; expected ≥ 90", got)
	}
}

// goldenFixturePath returns the absolute path to the golden
// YAML fixture. The fixture lives alongside this test file at
// `tools/api-docgen/testdata/endpoints.golden.yaml`.
func goldenFixturePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return filepath.Join(wd, "testdata", "endpoints.golden.yaml")
}

// manifestFixturePath returns the absolute path to the
// compact manifest fixture.
func manifestFixturePath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	return filepath.Join(wd, "testdata", "endpoints.manifest.txt")
}
