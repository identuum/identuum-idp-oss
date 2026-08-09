package runtime

import "testing"

// resolveHidePublicIDPEmailDomains: unset/empty/malformed ⇒ false (exposed,
// the safe default = current behavior); explicit truthy ⇒ true.
func TestResolveHidePublicIDPEmailDomains(t *testing.T) {
	cases := []struct {
		name string
		val  string // value returned by the stub getenv (unset ⇒ "")
		want bool
	}{
		{"unset ⇒ exposed (default)", "", false},
		{"whitespace ⇒ exposed (default)", "   ", false},
		{"malformed ⇒ exposed (safe default)", "yes-please", false},
		{"garbage ⇒ exposed (safe default)", "hide!!", false},
		{"true ⇒ hide", "true", true},
		{"1 ⇒ hide", "1", true},
		{"TRUE ⇒ hide", "TRUE", true},
		{" true (trimmed) ⇒ hide", "  true  ", true},
		{"false ⇒ exposed", "false", false},
		{"0 ⇒ exposed", "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k == "IDENTUUM_IDP_PUBLIC_HIDE_IDP_EMAIL_DOMAINS" {
					return tc.val
				}
				return ""
			}
			if got := resolveHidePublicIDPEmailDomains(getenv); got != tc.want {
				t.Errorf("resolveHidePublicIDPEmailDomains(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// A nil getenv must not panic (P-018) — it falls back to os.Getenv, which for
// an unset var yields the safe default (exposed).
func TestResolveHidePublicIDPEmailDomains_NilGetenvSafe(t *testing.T) {
	if resolveHidePublicIDPEmailDomains(nil) {
		t.Errorf("nil getenv should resolve to the exposed default (false)")
	}
}
