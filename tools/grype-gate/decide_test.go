package main

import (
	"os"
	"strings"
	"testing"
)

// THE-STALE-DEPENDENCY. `grype dir:. --fail-on high` passed on two advisories
// that had a published fix, because their severity was "Unknown" — and the
// finding rode in three consecutive slice reports with nothing failing.
//
// This rule pins the replacement: a finding with an available fix FAILS, an
// unfixable one does not, the severity floor is kept, and the only way past a
// fixable finding is an allowlist entry naming it WITH a reason and a ruling.

func fixable(id, pkg, ver, sev, fixedIn string) string {
	return `{"vulnerability":{"id":"` + id + `","severity":"` + sev +
		`","fix":{"state":"fixed","versions":["` + fixedIn + `"]}},` +
		`"artifact":{"name":"` + pkg + `","version":"` + ver + `"}}`
}

func unfixable(id, pkg, ver, sev string) string {
	return `{"vulnerability":{"id":"` + id + `","severity":"` + sev +
		`","fix":{"state":"not-fixed","versions":[]}},` +
		`"artifact":{"name":"` + pkg + `","version":"` + ver + `"}}`
}

func doc(t *testing.T, matches ...string) GrypeDoc {
	t.Helper()
	d, err := ParseDoc([]byte(`{"matches":[` + strings.Join(matches, ",") + `]}`))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return d
}

// RULE: GRYPE-FIXABLE-FAILS-1
func TestRule_GRYPE_FIXABLE_FAILS_1(t *testing.T) {
	// (1) THE DEFECT THIS SLICE FOUND, verbatim: two advisories against
	// golang.org/x/crypto v0.55.0, both fixed in 0.56.0, both severity
	// "Unknown". The old flag exited 0 on exactly this.
	theDefect := doc(t,
		fixable("GO-2026-6354", "golang.org/x/crypto", "v0.55.0", "Unknown", "0.56.0"),
		fixable("GO-2026-6355", "golang.org/x/crypto", "v0.55.0", "Unknown", "0.56.0"),
	)
	failures, line, ok := Decide(theDefect, Allowlist{})
	if ok {
		t.Fatalf("a finding with a published fix must FAIL; got pass with %q", line)
	}
	if len(failures) != 2 {
		t.Errorf("both advisories must fail; got %d (%q)", len(failures), line)
	}
	for _, want := range []string{"GO-2026-6354", "GO-2026-6355", "0.56.0", "fixable=2"} {
		if !strings.Contains(line, want) {
			t.Errorf("the failure line must name %q; got %q", want, line)
		}
	}

	// (2) An UNFIXABLE finding does not fail: no version bump can action it.
	// (GO-2026-5932 is real — govulncheck reports it against x/crypto with
	// "Fixed in: N/A" — and it must not wedge the gate shut.)
	if _, line, ok := Decide(doc(t, unfixable("GO-2026-5932", "golang.org/x/crypto", "v0.56.0", "Unknown")), Allowlist{}); !ok {
		t.Errorf("an unfixable finding must not fail the gate; got %q", line)
	} else if !strings.Contains(line, "unfixable=1") {
		t.Errorf("the pass line must still REPORT it; got %q", line)
	}

	// (3) THE SEVERITY FLOOR IS KEPT: High and Critical fail whether or not
	// a fix exists, so this gate is strictly stronger than --fail-on high.
	for _, sev := range []string{"High", "Critical", "high"} {
		if _, line, ok := Decide(doc(t, unfixable("CVE-X", "pkg", "1.0", sev)), Allowlist{}); ok {
			t.Errorf("severity %s must fail even with no fix; got %q", sev, line)
		}
	}

	// (4) The allowlist works ONLY by name, and only with a reason AND a
	// ruling. Same finding, four allowlist shapes.
	one := doc(t, fixable("GO-2026-6354", "golang.org/x/crypto", "v0.55.0", "Unknown", "0.56.0"))
	good := Allowlist{Entries: []AllowlistEntry{{
		ID: "GO-2026-6354", Reason: "the fix needs a code change costed at half a slice", Ruling: "owner, 2026-09-03", Added: "2026-09-03",
	}}}
	if _, line, ok := Decide(one, good); !ok {
		t.Errorf("a named entry with a reason and a ruling must pass; got %q", line)
	} else if !strings.Contains(line, "allowlisted=1") {
		t.Errorf("an allowlisted finding must still be COUNTED; got %q", line)
	}
	for name, bad := range map[string]Allowlist{
		"no reason": {Entries: []AllowlistEntry{{ID: "GO-2026-6354", Ruling: "owner"}}},
		"no ruling": {Entries: []AllowlistEntry{{ID: "GO-2026-6354", Reason: "because"}}},
		"no id":     {Entries: []AllowlistEntry{{Reason: "because", Ruling: "owner"}}},
	} {
		t.Run("malformed allowlist: "+name, func(t *testing.T) {
			_, line, ok := Decide(one, bad)
			if ok {
				t.Errorf("a malformed allowlist entry must not excuse anything; got %q", line)
			}
			if !strings.Contains(line, "malformed") {
				t.Errorf("the failure must name the malformed entry; got %q", line)
			}
		})
	}
	// An entry for a DIFFERENT id excuses nothing.
	other := Allowlist{Entries: []AllowlistEntry{{ID: "GO-2026-9999", Reason: "unrelated", Ruling: "owner"}}}
	if _, line, ok := Decide(one, other); ok {
		t.Errorf("an allowlist entry for another id must not excuse this one; got %q", line)
	}
	// An allowlist NEVER excuses a High severity.
	severeAllowed := Allowlist{Entries: []AllowlistEntry{{ID: "CVE-SEV", Reason: "r", Ruling: "owner"}}}
	if _, line, ok := Decide(doc(t, fixable("CVE-SEV", "pkg", "1.0", "High", "1.1")), severeAllowed); ok {
		t.Errorf("an allowlist must not excuse a High severity; got %q", line)
	}

	// (5) A clean scan passes and says so.
	if _, line, ok := Decide(doc(t), Allowlist{}); !ok || !strings.Contains(line, "matches=0 fixable=0") {
		t.Errorf("a clean scan must pass with a counted line; ok=%v line=%q", ok, line)
	}

	// (6) THE WIRING. A verdict nobody runs is not a gate: `make verify` must
	// drive this tool, and must not have kept the flag that let the defect
	// through.
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := string(makefile)
	if !strings.Contains(mk, "tools/grype-gate") {
		t.Errorf("the Makefile must drive tools/grype-gate")
	}
	// The RECIPE must not invoke the scanner directly any more — a comment
	// explaining why it was replaced is not an invocation, so only
	// non-comment lines count.
	for i, line := range strings.Split(mk, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "grype dir:") {
			t.Errorf("Makefile:%d invokes grype directly (%q): the bare scan exits 0 on a fixable finding", i+1, strings.TrimSpace(line))
		}
	}
	if !strings.Contains(mk, "grype-scan") {
		t.Errorf("the gate must stay wired under its existing target name so `make verify`'s plan is unchanged")
	}
}
