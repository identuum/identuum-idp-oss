package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE-GRYPE-SUBJECT (2026-09-12): the judge scans `dir:.` and relies on the
// committed .grype.yaml exclude list to keep gitignored build outputs out of
// the subject. On identuum-idp-ce that list (bin/**, identuum-idp, .gograph/**)
// did not cover `.dev-bin/identuum-idp` and `identuum-idp.test`, so a stale
// go1.26.5 dev binary raised eight stdlib advisories against a go1.27.1
// module. Two predicates, both hermetic — no scanner runs here:
//   (a) the configuration grype REPORTS about itself (descriptor.configuration)
//       equals the committed declaration;
//   (b) every gitignored executable the scan root holds is matched by an
//       exclude pattern — the predicate that would have caught the CE miss.

// declaration is the committed .grype.yaml of both repositories on
// 2026-09-12, minus the SUP-3 prose.
const declaration = `# comment
exclude:
  - ./bin/**
  - ./identuum-idp
  - ./.gograph/**
db:
  validate-age: true
  max-allowed-built-age: 120h

ignore:
  # GO-2026-5932 — no fix, not reachable.
  - vulnerability: GO-2026-5932
`

// effective is the shape grype 0.118.0 reports under descriptor.configuration
// for that declaration when run from /repo (measured 2026-09-12: excludes come
// back ABSOLUTE, durations in nanoseconds, the ignore list carries grype's
// four built-in kernel-header rules beside the declared one).
func effective(root string) string {
	return `{"matches":[],"descriptor":{"name":"grype","version":"0.118.0","configuration":{` +
		`"exclude":["` + root + `/bin/**","` + root + `/identuum-idp","` + root + `/.gograph/**"],` +
		`"db":{"validate-age":true,"max-allowed-built-age":432000000000000},` +
		`"ignore":[{"vulnerability":"GO-2026-5932"},{"package":{"name":"kernel-headers","type":"rpm","upstream-name":"kernel"},"match-type":"exact-indirect-match"}]}}}`
}

func TestCoverage_DeclarationReader(t *testing.T) {
	d, err := ReadDeclaration([]byte(declaration))
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	if got := strings.Join(d.Exclude, " "); got != "./bin/** ./identuum-idp ./.gograph/**" {
		t.Fatalf("exclude patterns: got %q", got)
	}
	if !d.ValidateAge || d.MaxAllowedBuiltAge != "120h" {
		t.Fatalf("db block: got validate-age=%v max-allowed-built-age=%q", d.ValidateAge, d.MaxAllowedBuiltAge)
	}
	if got := strings.Join(d.IgnoredVulnIDs, " "); got != "GO-2026-5932" {
		t.Fatalf("ignore ids: got %q", got)
	}
}

func TestCoverage_ConfigApplied(t *testing.T) {
	d, err := ReadDeclaration([]byte(declaration))
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	cfg, present, err := ParseScanConfig([]byte(effective("/repo")))
	if err != nil || !present {
		t.Fatalf("effective config: present=%v err=%v", present, err)
	}
	// (a) GREEN: what grype reports equals what is committed.
	if line, ok := CompareConfig(cfg, d, "/repo"); !ok {
		t.Fatalf("applied configuration must pass; got %q", line)
	}
	// (a) RED, three ways: a dropped exclude, a loosened db age, a missing ignore.
	dropped := strings.Replace(effective("/repo"), `"/repo/identuum-idp",`, "", 1)
	cfg, _, _ = ParseScanConfig([]byte(dropped))
	if line, ok := CompareConfig(cfg, d, "/repo"); ok || !strings.Contains(line, "./identuum-idp") {
		t.Fatalf("a dropped exclude must fail and be named; got ok=%v %q", ok, line)
	}
	loosened := strings.Replace(effective("/repo"), "432000000000000", "864000000000000", 1)
	cfg, _, _ = ParseScanConfig([]byte(loosened))
	if line, ok := CompareConfig(cfg, d, "/repo"); ok || !strings.Contains(line, "max-allowed-built-age") {
		t.Fatalf("a loosened db age must fail and be named; got ok=%v %q", ok, line)
	}
	missing := strings.Replace(effective("/repo"), `{"vulnerability":"GO-2026-5932"},`, "", 1)
	cfg, _, _ = ParseScanConfig([]byte(missing))
	if line, ok := CompareConfig(cfg, d, "/repo"); ok || !strings.Contains(line, "GO-2026-5932") {
		t.Fatalf("a missing ignore must fail and be named; got ok=%v %q", ok, line)
	}
	// A report without descriptor.configuration is not a pass: present=false.
	if _, present, err := ParseScanConfig([]byte(`{"matches":[]}`)); present || err != nil {
		t.Fatalf("no descriptor.configuration must read absent; got present=%v err=%v", present, err)
	}
}

// TestCoverage_LapsedSuppressionIsAFinding — THE-EIGHT-QUICK-ONES, OSS 2
// (2026-09-16). The committed file's own rule says an ignore entry past its
// re-check date is a finding about the file; nothing enforced it. A
// past-dated entry is RED and names the entry and the date; an entry with no
// date at all is RED; the section-level RE-CHECK covers an entry without its
// own; a future date is green; the real .grype.yaml is green today.
func TestCoverage_LapsedSuppressionIsAFinding(t *testing.T) {
	today := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	fixture := func(comment string) string {
		return "exclude:\n  - ./bin/**\ndb:\n  validate-age: true\n  max-allowed-built-age: 120h\n" +
			"# RE-CHECK 2027-01-01 (quarterly).\nignore:\n" + comment + "  - vulnerability: GO-2026-5932\n"
	}
	d, err := ReadDeclaration([]byte(fixture("  # NO FIX AVAILABLE. Re-check 2026-09-01, or sooner.\n")))
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	if d.RecheckDates["GO-2026-5932"] != "2026-09-01" || d.RecheckDefault != "2027-01-01" {
		t.Fatalf("dates not read: entry=%q default=%q", d.RecheckDates["GO-2026-5932"], d.RecheckDefault)
	}
	line, ok := LapsedSuppressions(d, today)
	if ok || !strings.Contains(line, "GO-2026-5932") || !strings.Contains(line, "2026-09-01") || !strings.HasPrefix(line, "check FAILED:") {
		t.Fatalf("a lapsed re-check date must be a RED finding naming the entry and the date; got ok=%v %q", ok, line)
	}
	// A future date on the entry is green.
	d, _ = ReadDeclaration([]byte(fixture("  # Re-check 2026-12-31.\n")))
	if line, ok := LapsedSuppressions(d, today); !ok {
		t.Fatalf("a future re-check date must pass; got %q", line)
	}
	// No date of its own: the section's RE-CHECK covers it (future → green).
	d, _ = ReadDeclaration([]byte(fixture("  # NO FIX AVAILABLE.\n")))
	if line, ok := LapsedSuppressions(d, today); !ok {
		t.Fatalf("the section date must cover an entry without its own; got %q", line)
	}
	// No date anywhere is a finding too: the file's rule requires one.
	undated := strings.Replace(fixture("  # NO FIX AVAILABLE.\n"), "# RE-CHECK 2027-01-01 (quarterly).\n", "", 1)
	d, _ = ReadDeclaration([]byte(undated))
	if line, ok := LapsedSuppressions(d, today); ok || !strings.Contains(line, "GO-2026-5932") || !strings.Contains(line, "no re-check date") {
		t.Fatalf("an undated suppression must be a RED finding; got ok=%v %q", ok, line)
	}
	// The section date lapsed and the entry has none: red, naming both.
	d, _ = ReadDeclaration([]byte(strings.Replace(fixture("  # NO FIX AVAILABLE.\n"), "2027-01-01", "2026-01-01", 1)))
	if line, ok := LapsedSuppressions(d, today); ok || !strings.Contains(line, "2026-01-01") {
		t.Fatalf("a lapsed section date must fail an entry without its own; got ok=%v %q", ok, line)
	}
	// The committed file, today.
	raw, err := os.ReadFile("../../.grype.yaml")
	if err != nil {
		t.Fatalf("read .grype.yaml: %v", err)
	}
	real, err := ReadDeclaration(raw)
	if err != nil {
		t.Fatalf("committed declaration: %v", err)
	}
	if line, ok := LapsedSuppressions(real, time.Now().UTC()); !ok {
		t.Fatalf("the committed .grype.yaml is lapsed today: %q", line)
	}
	if len(real.RecheckDates) == 0 && real.RecheckDefault == "" {
		t.Fatal("the committed .grype.yaml carries no re-check date the gate can read")
	}
}

// inventoryDoc builds a CycloneDX-JSON inventory in the shape grype 0.118.0
// writes for `-o cyclonedx-json` (measured 2026-09-16 on this tree: 78
// components, 75 of them libraries carrying `syft:location:N:path`
// properties whose values are root-relative with a leading slash, 3 of them
// `file` components whose NAME is the absolute path and which carry no
// location property).
func inventoryDoc(locations []string, fileNames []string) string {
	var comps []string
	for i, l := range locations {
		comps = append(comps, fmt.Sprintf(`{"bom-ref":"c%d","type":"library","name":"lib%d","version":"1.0.0","properties":[{"name":"syft:package:type","value":"go-module"},{"name":"syft:location:0:path","value":%q}]}`, i, i, l))
	}
	for i, n := range fileNames {
		comps = append(comps, fmt.Sprintf(`{"bom-ref":"f%d","type":"file","name":%q}`, i, n))
	}
	return `{"$schema":"http://cyclonedx.org/schema/bom-1.7.schema.json","bomFormat":"CycloneDX","specVersion":"1.7","version":1,"metadata":{"component":{"bom-ref":"root","type":"file","name":"."}},"components":[` + strings.Join(comps, ",") + `]}`
}

// TestCoverage_InventoryIsWhatGrypeSaw — THE-SCANNER-THAT-SAYS-WHAT-IT-SAW
// (2026-09-16). The coverage predicate no longer predicts what grype will
// scan (gitignored files with an execute bit, matched by OUR reading of the
// exclude patterns); it reads what grype SAW — the CycloneDX inventory — and
// fails when any component was catalogued at a path git reports as ignored.
// RED FIRST: none of ParseInventory, ListIgnoredPaths or InventoryDecide
// existed when this test was written.
func TestCoverage_InventoryIsWhatGrypeSaw(t *testing.T) {
	root := "/repo"
	// A component catalogued under an ignored path is a RED finding naming it.
	inv, err := ParseInventory([]byte(inventoryDoc([]string{"/go.mod", "/bin/tool/go.mod"}, nil)), root)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if inv.Components != 2 || len(inv.Locations) != 2 {
		t.Fatalf("inventory = %+v, want 2 components at 2 locations", inv)
	}
	seen, line, ok := InventoryDecide(inv, []string{"bin", "identuum-idp"})
	if ok || len(seen) != 1 || seen[0] != "bin/tool/go.mod" || !strings.HasPrefix(line, "check FAILED: grype-gate coverage:") || !strings.Contains(line, "bin/tool/go.mod") {
		t.Fatalf("a location under an ignored path must fail and be named; got ok=%v seen=%v %q", ok, seen, line)
	}
	// A `file` component names its path absolutely; under an ignored path it
	// fails the same way, as the path relative to the root.
	inv, _ = ParseInventory([]byte(inventoryDoc(nil, []string{root + "/identuum-idp", root + "/go.mod"})), root)
	if inv.Components != 2 || len(inv.Locations) != 2 {
		t.Fatalf("file components must count and locate; got %+v", inv)
	}
	if seen, line, ok := InventoryDecide(inv, []string{"identuum-idp"}); ok || len(seen) != 1 || seen[0] != "identuum-idp" || !strings.Contains(line, "identuum-idp") {
		t.Fatalf("an ignored file component must fail; got ok=%v seen=%v %q", ok, seen, line)
	}
	// A clean inventory passes, and the line says what was judged.
	inv, _ = ParseInventory([]byte(inventoryDoc([]string{"/go.mod", "/.github/workflows/ci.yml"}, []string{root + "/go.mod"})), root)
	seen, line, ok = InventoryDecide(inv, []string{"bin", "identuum-idp", ".gograph"})
	if !ok || len(seen) != 0 || !strings.Contains(line, "3 component(s)") || !strings.Contains(line, "none under") {
		t.Fatalf("a clean inventory must pass and say so; got ok=%v seen=%v %q", ok, seen, line)
	}
	// An ignored path matches itself and what lies below it, never a sibling
	// that merely shares its prefix.
	inv, _ = ParseInventory([]byte(inventoryDoc([]string{"/binary/go.mod", "/bin"}, nil)), root)
	if seen, _, ok := InventoryDecide(inv, []string{"bin"}); ok || len(seen) != 1 || seen[0] != "bin" {
		t.Fatalf("prefix semantics: want exactly [bin] seen; got ok=%v %v", ok, seen)
	}
	// No components is not a pass: the inventory cannot be judged.
	if _, err := ParseInventory([]byte(inventoryDoc(nil, nil)), root); err == nil || !strings.Contains(err.Error(), "no components") {
		t.Fatalf("an empty inventory must be refused; got %v", err)
	}
	// Not a CycloneDX document is not an inventory.
	if _, err := ParseInventory([]byte(`{"matches":[]}`), root); err == nil {
		t.Fatal("a grype JSON report is not a CycloneDX inventory and must be refused")
	}
}

// TestCoverage_IgnoredPathsAreGitsAnswer: the ignored set is what git reports
// (`git status --ignored --porcelain`), directories without their trailing
// slash, never a guess from execute bits.
func TestCoverage_IgnoredPathsAreGitsAnswer(t *testing.T) {
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
	must(os.WriteFile(filepath.Join(root, ".gitignore"), []byte("bin/\nstray\n*.test\n"), 0o600))
	must(os.MkdirAll(filepath.Join(root, "bin"), 0o755))
	must(os.WriteFile(filepath.Join(root, "bin", "tool"), []byte("#!/bin/sh\n"), 0o755))
	must(os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600))
	must(os.WriteFile(filepath.Join(root, "unit.test"), []byte("x"), 0o600))
	must(os.WriteFile(filepath.Join(root, "kept.txt"), []byte("x"), 0o600))
	got, err := ListIgnoredPaths(root)
	if err != nil {
		t.Fatalf("ListIgnoredPaths: %v", err)
	}
	if want := "bin stray unit.test"; strings.Join(got, " ") != want {
		t.Fatalf("ignored = %v, want %q", got, want)
	}
}
