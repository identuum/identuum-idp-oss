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
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
}

// ReadDeclaration reads the three blocks the gate pins from the committed
// .grype.yaml. It understands exactly the shape that file has — top-level
// keys, two-space list items, `key: value` pairs — and nothing more; a shape
// it does not understand is an error, never a silent empty declaration.
func ReadDeclaration(raw []byte) (Declaration, error) {
	var d Declaration
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
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
				d.IgnoredVulnIDs = append(d.IgnoredVulnIDs, strings.TrimSpace(val))
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

// IgnoredEntry is one gitignored executable under the scan root, as a
// slash-separated path relative to it.
type IgnoredEntry struct {
	Path string
}

// Excluded reports whether rel is matched by any of the declared patterns,
// with the semantics the committed file relies on: `./dir/**` covers the
// directory and everything below it; a bare `./name` covers exactly that
// path; any other pattern is a path.Match glob against the whole path.
func Excluded(rel string, patterns []string) bool {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	for _, p := range patterns {
		p = strings.TrimPrefix(p, "./")
		if dir, ok := strings.CutSuffix(p, "/**"); ok {
			if rel == dir || strings.HasPrefix(rel, dir+"/") {
				return true
			}
			continue
		}
		if rel == p {
			return true
		}
		if m, err := path.Match(p, rel); err == nil && m {
			return true
		}
	}
	return false
}

// CoverageDecide is predicate (b): every gitignored executable is excluded.
func CoverageDecide(entries []IgnoredEntry, patterns []string) (uncovered []string, line string, ok bool) {
	for _, e := range entries {
		if !Excluded(e.Path, patterns) {
			uncovered = append(uncovered, e.Path)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		return uncovered, fmt.Sprintf(
			"check FAILED: grype-gate coverage: %d gitignored executable(s) outside .grype.yaml's exclude list — %s — the scanner would judge them as the tree; exclude them by name or remove them",
			len(uncovered), strings.Join(uncovered, ", ")), false
	}
	return nil, fmt.Sprintf("coverage: %d gitignored executable(s), all excluded (%s)",
		len(entries), strings.Join(patterns, ", ")), true
}

// ListIgnoredExecutables walks every path git reports as ignored under root
// and returns the regular files that are executable or `*.test` binaries.
func ListIgnoredExecutables(root string) ([]IgnoredEntry, error) {
	cmd := exec.Command("git", "-C", root, "status", "--ignored", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git status --ignored: %w", err)
	}
	var entries []IgnoredEntry
	for l := range strings.SplitSeq(string(out), "\n") {
		p, ok := strings.CutPrefix(l, "!! ")
		if !ok {
			continue
		}
		full := filepath.Join(root, p)
		walkErr := filepath.WalkDir(full, func(fp string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				return nil
			}
			info, err := de.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if info.Mode().Perm()&0o111 != 0 || strings.HasSuffix(fp, ".test") {
				rel, err := filepath.Rel(root, fp)
				if err != nil {
					return err
				}
				entries = append(entries, IgnoredEntry{Path: filepath.ToSlash(rel)})
			}
			return nil
		})
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				continue
			}
			return nil, fmt.Errorf("walk %s: %w", p, walkErr)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
