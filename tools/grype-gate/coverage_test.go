package main

import (
	"os"
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

func TestCoverage_IgnoredExecutablesMustBeExcluded(t *testing.T) {
	d, err := ReadDeclaration([]byte(declaration))
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	// THE CE MISS, verbatim: three gitignored executables on identuum-idp-ce on
	// 2026-09-12. bin/identuum-idp is covered by ./bin/**; the other two are not.
	ce := []IgnoredEntry{
		{Path: ".dev-bin/identuum-idp"},
		{Path: "bin/identuum-idp"},
		{Path: "identuum-idp.test"},
	}
	uncovered, line, ok := CoverageDecide(ce, d.Exclude)
	if ok {
		t.Fatalf("CE's tree must FAIL coverage; got pass %q", line)
	}
	if got := strings.Join(uncovered, " "); got != ".dev-bin/identuum-idp identuum-idp.test" {
		t.Fatalf("the uncovered set must be exactly the two CE artifacts; got %q", got)
	}
	for _, want := range []string{".dev-bin/identuum-idp", "identuum-idp.test", "check FAILED"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the failure line must carry %q; got %q", want, line)
		}
	}
	// identuum-idp-oss on 2026-09-12: five gitignored executables, all covered.
	oss := []IgnoredEntry{
		{Path: "bin/identuum-idp"}, {Path: "bin/grype-gate"}, {Path: "bin/api-docgen"},
		{Path: "bin/integration-witness"}, {Path: "identuum-idp"},
	}
	if _, line, ok := CoverageDecide(oss, d.Exclude); !ok || !strings.Contains(line, "all excluded") {
		t.Fatalf("OSS's tree must pass coverage; got ok=%v %q", ok, line)
	}
	// Pattern semantics pinned: a `/**` pattern covers the directory itself and
	// everything below it; a bare name covers only that path.
	for rel, want := range map[string]bool{
		"bin":                   true,
		"bin/x/y":               true,
		"identuum-idp":          true,
		"identuum-idp.test":     false,
		"identuum-idp/inner":    false,
		".gograph/graph.json":   true,
		".dev-bin/identuum-idp": false,
	} {
		if got := Excluded(rel, d.Exclude); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", rel, got, want)
		}
	}
}
