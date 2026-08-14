// Command rulefloorlite is the IN-REPO static floor for one-repo checkouts —
// CI cannot see the sibling ../rulefloor checkout, so without this the remote
// pipeline runs no ledger check at all. It is a DELIBERATE SUBSET of
// `rulefloor check`:
//
//   - strict parse of RULE-FLOOR.md (FLOOR line, header, six non-empty cells)
//   - row count >= FLOOR
//   - every armed row's check file exists
//   - the row's tag is present in that file ("[ID]" for *.spec.ts,
//     "// RULE: ID" for *_test.go)
//   - a *.spec.ts line carrying the "[ID]" tag must not carry .skip( or .only(
//
// NO HASH VERIFICATION, no body extraction, no test execution, no orphan
// scan: hashing and extraction stay the rulefloor tool's alone, and this
// floor only refuses the coarse regressions a one-repo checkout can still
// detect. Exit 0 clean; exit 1 on any failure or parse fault.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	repo := "."
	if len(os.Args) > 1 {
		repo = os.Args[1]
	}
	problems, err := liteCheck(repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rulefloorlite: "+err.Error())
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Println("FAIL " + p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "rulefloorlite: %d problem(s)\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("rulefloorlite OK (static subset; hashes are rulefloor's job)")
}

type liteRow struct {
	id, check string
}

// liteCheck returns per-row problems, or an error for parse faults.
func liteCheck(repo string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(repo, "RULE-FLOOR.md"))
	if err != nil {
		return nil, err
	}
	floor := -1
	var rows []liteRow
	stage := 0
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch stage {
		case 0:
			num, ok := strings.CutPrefix(line, "FLOOR: ")
			if !ok {
				return nil, fmt.Errorf("line %d: expected \"FLOOR: N\"", i+1)
			}
			n, err := strconv.Atoi(strings.TrimSpace(num))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("line %d: invalid FLOOR", i+1)
			}
			floor = n
			stage = 1
		case 1, 2:
			stage++ // header, separator — shape-checked by cell count below
		default:
			cells := strings.Split(line, "|")
			if len(cells) != 8 || strings.TrimSpace(cells[0]) != "" || strings.TrimSpace(cells[7]) != "" {
				return nil, fmt.Errorf("line %d: malformed row", i+1)
			}
			for _, c := range cells[1:7] {
				if strings.TrimSpace(c) == "" {
					return nil, fmt.Errorf("line %d: missing field", i+1)
				}
			}
			rows = append(rows, liteRow{
				id:    strings.TrimSpace(cells[1]),
				check: strings.TrimSpace(cells[4]),
			})
		}
	}
	if stage < 3 {
		return nil, fmt.Errorf("truncated ledger")
	}
	var problems []string
	if len(rows) < floor {
		problems = append(problems, fmt.Sprintf("ledger: %d rows is below FLOOR %d", len(rows), floor))
	}
	for _, r := range rows {
		if r.check == "NONE" {
			continue
		}
		file, _, ok := strings.Cut(r.check, " @ ")
		if !ok {
			problems = append(problems, r.id+": malformed check field")
			continue
		}
		file = strings.TrimSpace(file)
		body, err := os.ReadFile(filepath.Join(repo, file))
		if err != nil {
			problems = append(problems, r.id+": check file missing: "+file)
			continue
		}
		src := string(body)
		switch {
		case strings.HasSuffix(file, ".spec.ts"):
			tag := "[" + r.id + "]"
			found := false
			for _, ln := range strings.Split(src, "\n") {
				if !strings.Contains(ln, tag) {
					continue
				}
				found = true
				if strings.Contains(ln, ".skip(") || strings.Contains(ln, ".only(") {
					problems = append(problems, r.id+": tagged title line carries .skip/.only in "+file)
				}
			}
			if !found {
				problems = append(problems, r.id+": tag "+tag+" absent from "+file)
			}
		case strings.HasSuffix(file, "_test.go"):
			if !strings.Contains(src, "// RULE: "+r.id) {
				problems = append(problems, r.id+": tag \"// RULE: "+r.id+"\" absent from "+file)
			}
		default:
			problems = append(problems, r.id+": unknown check file kind: "+file)
		}
	}
	return problems, nil
}
