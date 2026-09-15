package main

// THE-GRYPE-SUBJECT (2026-09-12). The judge scans `dir:.`; the committed
// .grype.yaml keeps gitignored build outputs out of that subject by NAME
// (bin/**, identuum-idp, .gograph/**). On identuum-idp-ce that list did not
// cover `.dev-bin/identuum-idp` and `identuum-idp.test`, so a stale go1.26.5
// dev binary raised eight stdlib advisories against a go1.27.1 module: the
// config was applied, the list did not cover the repository. Two predicates
// close that gap without changing the subject and without a scanner in the
// tests:
//
//   (a) APPLIED — the configuration grype REPORTS about itself
//       (descriptor.configuration: exclude, db ages, ignore) equals the
//       committed declaration. The tool is asked about itself; the declared
//       side is read from the committed file by the same reader (b) uses,
//       so there is ONE exclusion list in this repository.
//   (b) COVERAGE — every gitignored EXECUTABLE the scan root holds (a regular
//       file with an execute bit, or a `*.test` binary from `go test -c`) is
//       matched by an exclude pattern. Pure git + filesystem + config; the
//       scanner is never consulted. Measured 2026-09-12: identuum-idp-oss holds
//       five such files, all covered; identuum-idp-ce holds three, two
//       uncovered — the predicate that would have caught the miss.
//
// Exit discipline is main.go's: 0 pass, 1 fail, 2 cannot-evaluate.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Declaration is what the committed .grype.yaml declares, read by the one
// reader this package has for it: the `exclude:` list, the two `db:` keys the
// gate pins, and the `ignore:` vulnerability ids.
type Declaration struct {
	Exclude            []string
	ValidateAge        bool
	MaxAllowedBuiltAge string
	IgnoredVulnIDs     []string
	// RecheckDates maps an ignored vulnerability id to the re-check date its
	// own comment carries ("Re-check YYYY-MM-DD"); RecheckDefault is the
	// ignore section's "RE-CHECK YYYY-MM-DD" that covers an entry without
	// one. THE-EIGHT-QUICK-ONES, OSS 2 (2026-09-16): the file's own rule —
	// "an entry past its date is a finding about this file" — was enforced
	// by nothing, so a suppression could outlive its review forever.
	RecheckDates   map[string]string
	RecheckDefault string
}

// recheckDateRe finds a re-check date in a comment line, in either spelling
// the committed file uses ("Re-check 2026-11-04", "RE-CHECK 2026-11-04").
var recheckDateRe = regexp.MustCompile(`(?i)\bre-check\s+(\d{4}-\d{2}-\d{2})`)

// LapsedSuppressions is the date half of the config predicate: every ignored
// vulnerability must carry a re-check date (its own, or the section's), and a
// date before today is a RED finding naming the entry and the date. The
// suppression itself is never touched; renewing or deleting it is a human's
// review, which this makes overdue rather than invisible.
func LapsedSuppressions(d Declaration, today time.Time) (line string, ok bool) {
	day := today.UTC().Format("2006-01-02")
	var problems []string
	for _, id := range d.IgnoredVulnIDs {
		date, source := d.RecheckDates[id], "its own"
		if date == "" {
			date, source = d.RecheckDefault, "the section's"
		}
		switch {
		case date == "":
			problems = append(problems, "suppression "+id+" carries no re-check date (neither its own nor the ignore section's)")
		case date < day:
			problems = append(problems, fmt.Sprintf("suppression %s re-check date %s (%s) has lapsed, today is %s", id, date, source, day))
		}
	}
	if len(problems) > 0 {
		return "check FAILED: grype-gate config: " + strings.Join(problems, "; ") +
			" — renew or delete the entry; a lapsed suppression is a finding about .grype.yaml", false
	}
	return fmt.Sprintf("re-check: %d declared ignore(s), none lapsed on %s", len(d.IgnoredVulnIDs), day), true
}

// ReadDeclaration reads the three blocks the gate pins from the committed
// .grype.yaml. It understands exactly the shape that file has — top-level
// keys, two-space list items, `key: value` pairs — and nothing more; a shape
// it does not understand is an error, never a silent empty declaration.
func ReadDeclaration(raw []byte) (Declaration, error) {
	var d Declaration
	d.RecheckDates = map[string]string{}
	section := ""
	// pendingDate is the last "Re-check YYYY-MM-DD" seen in the comment
	// run that precedes the next ignore entry; a top-level "RE-CHECK" comment
	// is the section default.
	pendingDate := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			if m := recheckDateRe.FindStringSubmatch(trim); m != nil {
				if strings.HasPrefix(line, "#") {
					d.RecheckDefault = m[1]
				} else {
					pendingDate = m[1]
				}
			}
			continue
		}
		if !strings.HasPrefix(line, " ") {
			key, rest, _ := strings.Cut(trim, ":")
			section = strings.TrimSpace(key)
			if strings.TrimSpace(rest) != "" {
				return d, fmt.Errorf(".grype.yaml: top-level %q carries an inline value; the gate reads block form only", section)
			}
			continue
		}
		switch section {
		case "exclude":
			item, ok := strings.CutPrefix(trim, "- ")
			if !ok {
				return d, fmt.Errorf(".grype.yaml: exclude entry %q is not a list item", trim)
			}
			d.Exclude = append(d.Exclude, strings.TrimSpace(item))
		case "db":
			key, val, ok := strings.Cut(trim, ":")
			if !ok {
				return d, fmt.Errorf(".grype.yaml: db entry %q is not key: value", trim)
			}
			switch strings.TrimSpace(key) {
			case "validate-age":
				d.ValidateAge = strings.TrimSpace(val) == "true"
			case "max-allowed-built-age":
				d.MaxAllowedBuiltAge = strings.TrimSpace(val)
			}
		case "ignore":
			item, ok := strings.CutPrefix(trim, "- ")
			if !ok {
				continue // a continuation line of a multi-key ignore entry
			}
			key, val, _ := strings.Cut(item, ":")
			if strings.TrimSpace(key) == "vulnerability" {
				id := strings.TrimSpace(val)
				d.IgnoredVulnIDs = append(d.IgnoredVulnIDs, id)
				if pendingDate != "" {
					d.RecheckDates[id] = pendingDate
				}
				pendingDate = ""
			}
		}
	}
	if err := sc.Err(); err != nil {
		return d, err
	}
	if len(d.Exclude) == 0 {
		return d, fmt.Errorf(".grype.yaml: no exclude list — the gate cannot judge coverage without a declaration")
	}
	return d, nil
}

// ScanConfig is the configuration grype reports about ITSELF in its JSON
// report (descriptor.configuration), measured against grype 0.118.0: excludes
// come back as absolute paths, durations as nanoseconds, and the ignore list
// carries grype's built-in rules beside the declared ones.
type ScanConfig struct {
	Exclude            []string
	ValidateAge        bool
	MaxAllowedBuiltAge int64
	IgnoredVulnIDs     []string
}

// ParseScanConfig reads descriptor.configuration from a grype JSON report.
// present is false when the report carries no such block: a scanner that does
// not say what it applied cannot be judged applied.
func ParseScanConfig(raw []byte) (cfg ScanConfig, present bool, err error) {
	var doc struct {
		Descriptor struct {
			Configuration *struct {
				Exclude []string `json:"exclude"`
				DB      struct {
					ValidateAge        bool  `json:"validate-age"`
					MaxAllowedBuiltAge int64 `json:"max-allowed-built-age"`
				} `json:"db"`
				Ignore []struct {
					Vulnerability string `json:"vulnerability"`
				} `json:"ignore"`
			} `json:"configuration"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return cfg, false, fmt.Errorf("grype output: invalid JSON: %w", err)
	}
	c := doc.Descriptor.Configuration
	if c == nil {
		return cfg, false, nil
	}
	cfg.Exclude = c.Exclude
	cfg.ValidateAge = c.DB.ValidateAge
	cfg.MaxAllowedBuiltAge = c.DB.MaxAllowedBuiltAge
	for _, ig := range c.Ignore {
		if ig.Vulnerability != "" {
			cfg.IgnoredVulnIDs = append(cfg.IgnoredVulnIDs, ig.Vulnerability)
		}
	}
	return cfg, true, nil
}

// CompareConfig is predicate (a): the effective configuration equals the
// committed declaration. root is the absolute scan root, because grype
// reports excludes resolved against it.
func CompareConfig(cfg ScanConfig, d Declaration, root string) (line string, ok bool) {
	var problems []string

	want := map[string]bool{}
	for _, p := range d.Exclude {
		want[filepath.Join(root, strings.TrimPrefix(p, "./"))] = true
	}
	got := map[string]bool{}
	for _, p := range cfg.Exclude {
		got[p] = true
	}
	for _, p := range d.Exclude {
		if !got[filepath.Join(root, strings.TrimPrefix(p, "./"))] {
			problems = append(problems, "declared exclude "+p+" is not in effect")
		}
	}
	for p := range got {
		if !want[p] {
			problems = append(problems, "effective exclude "+p+" is not declared")
		}
	}

	if cfg.ValidateAge != d.ValidateAge {
		problems = append(problems, fmt.Sprintf("db.validate-age effective=%v declared=%v", cfg.ValidateAge, d.ValidateAge))
	}
	if dur, err := time.ParseDuration(d.MaxAllowedBuiltAge); err != nil {
		problems = append(problems, "db.max-allowed-built-age declared "+d.MaxAllowedBuiltAge+" is not a duration")
	} else if dur.Nanoseconds() != cfg.MaxAllowedBuiltAge {
		problems = append(problems, fmt.Sprintf("db.max-allowed-built-age effective=%s declared=%s",
			time.Duration(cfg.MaxAllowedBuiltAge), dur))
	}

	effIgnore := map[string]bool{}
	for _, id := range cfg.IgnoredVulnIDs {
		effIgnore[id] = true
	}
	for _, id := range d.IgnoredVulnIDs {
		if !effIgnore[id] {
			problems = append(problems, "declared ignore "+id+" is not in effect")
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return "check FAILED: grype-gate config: what grype applied is not the committed .grype.yaml — " +
			strings.Join(problems, "; "), false
	}
	return fmt.Sprintf("config applied (%d exclude(s), db max-allowed-built-age %s, %d declared ignore(s))",
		len(d.Exclude), d.MaxAllowedBuiltAge, len(d.IgnoredVulnIDs)), true
}

// THE-SCANNER-THAT-SAYS-WHAT-IT-SAW (2026-09-16). Predicate (b) no longer
// PREDICTS what grype will scan — until this slice it listed gitignored files
// with an execute bit or a *.test name and matched them against the exclude
// patterns with OUR reading of the patterns, so a divergence between that
// reading and grype's, or a non-executable manifest grype catalogues, passed
// as covered while grype scanned anyway. It now reads what grype SAW: the
// CycloneDX inventory of the same scan (`-o cyclonedx-json`), whose
// components carry the path each was catalogued at, and it fails when any
// such path is one git reports as ignored. The tool is asked about itself;
// no second list of what the scanner sees survives beside the scanner's own.

// Inventory is what grype saw: the components of its CycloneDX-JSON report
// and the paths they were catalogued at, root-relative and slash-separated.
type Inventory struct {
	Components int
	Locations  []string
}

// ParseInventory reads a CycloneDX-JSON inventory as grype 0.118.0 writes it
// (measured 2026-09-16): a library component carries one or more
// `syft:location:N:path` properties whose values are root-relative with a
// leading slash; a `file` component carries the absolute path in its name and
// no location property. root is the absolute scan root the absolute names are
// resolved against. An inventory that is not CycloneDX, or holds no
// components, cannot be judged and is an error.
func ParseInventory(raw []byte, root string) (Inventory, error) {
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Type       string `json:"type"`
			Name       string `json:"name"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Inventory{}, fmt.Errorf("grype inventory: invalid JSON: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return Inventory{}, fmt.Errorf("grype inventory: not a CycloneDX document (bomFormat %q) — the coverage predicate reads what grype saw and this is not that", doc.BOMFormat)
	}
	if len(doc.Components) == 0 {
		return Inventory{}, errors.New("grype inventory: no components — an inventory that saw nothing cannot be judged")
	}
	inv := Inventory{Components: len(doc.Components)}
	seen := map[string]bool{}
	keep := func(p string) {
		p = strings.TrimPrefix(filepath.ToSlash(p), "/")
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		inv.Locations = append(inv.Locations, p)
	}
	for _, c := range doc.Components {
		// A location property is root-relative by syft's convention: its
		// leading slash is the scan root, not the filesystem root.
		for _, prop := range c.Properties {
			if strings.HasPrefix(prop.Name, "syft:location:") && strings.HasSuffix(prop.Name, ":path") {
				keep(prop.Value)
			}
		}
		// A `file` component's name is the absolute path on this machine;
		// one outside the root is not this subject's and is dropped.
		if c.Type == "file" && c.Name != "" {
			name := filepath.ToSlash(c.Name)
			if filepath.IsAbs(name) {
				rel, err := filepath.Rel(root, name)
				if err != nil || rel == "." || strings.HasPrefix(rel, "../") {
					continue
				}
				name = rel
			}
			keep(name)
		}
	}
	sort.Strings(inv.Locations)
	return inv, nil
}

// ListIgnoredPaths is git's own answer to "what is ignored here":
// `git status --ignored --porcelain`, the `!! ` entries, directories without
// their trailing slash, slash-separated, sorted.
func ListIgnoredPaths(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "status", "--ignored", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git status --ignored: %w", err)
	}
	var paths []string
	for l := range strings.SplitSeq(string(out), "\n") {
		p, ok := strings.CutPrefix(l, "!! ")
		if !ok {
			continue
		}
		p = strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(p)), "/")
		if p != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// InventoryDecide is predicate (b): no component grype catalogued sits at a
// path git ignores — the path itself or anything below it. seen names the
// offending locations, sorted.
func InventoryDecide(inv Inventory, ignored []string) (seen []string, line string, ok bool) {
	for _, loc := range inv.Locations {
		for _, ig := range ignored {
			if loc == ig || strings.HasPrefix(loc, ig+"/") {
				seen = append(seen, loc)
				break
			}
		}
	}
	sort.Strings(seen)
	if len(seen) > 0 {
		return seen, fmt.Sprintf(
			"check FAILED: grype-gate coverage: %d of %d component location(s) grype catalogued lie under a gitignored path — %s — the scanner saw what the exclude list was to keep out of the tree; exclude them by name in .grype.yaml or remove them",
			len(seen), len(inv.Locations), strings.Join(seen, ", ")), false
	}
	return nil, fmt.Sprintf("coverage: inventory %d component(s) at %d location(s), none under an ignored path (%d ignored path(s) read from git)",
		inv.Components, len(inv.Locations), len(ignored)), true
}
