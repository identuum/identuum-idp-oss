package runtime

import "testing"

func TestResolveAllowMultiReplica(t *testing.T) {
	cases := []struct {
		name string
		val  string
		set  bool
		want bool
	}{
		{name: "unset", set: false, want: false},
		{name: "empty", val: "", set: true, want: false},
		{name: "malformed", val: "yesplease", set: true, want: false},
		{name: "true", val: "true", set: true, want: true},
		{name: "1", val: "1", set: true, want: true},
		{name: "TRUE", val: "TRUE", set: true, want: true},
		{name: "false", val: "false", set: true, want: false},
		{name: "0", val: "0", set: true, want: false},
		{name: "whitespace-true", val: "  true  ", set: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string {
				if k == "IDENTUUM_IDP_ALLOW_MULTI_REPLICA" && tc.set {
					return tc.val
				}
				return ""
			}
			if got := resolveAllowMultiReplica(getenv); got != tc.want {
				t.Fatalf("resolveAllowMultiReplica(%q)=%v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// TestResolveAllowMultiReplica_NilGetenvSafe: a nil getenv falls back to
// os.Getenv and never panics (mirrors the other config resolvers).
func TestResolveAllowMultiReplica_NilGetenvSafe(t *testing.T) {
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	if !resolveAllowMultiReplica(nil) {
		t.Fatal("nil getenv must fall back to os.Getenv and read the set value")
	}
}
