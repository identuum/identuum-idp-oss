package postgres

import "testing"

// TestResolveDefaultMaxSessionsPerUser pins the DEFAULT_MAX_SESSIONS_PER_USER
// env-override migration (F1 fix): the value is now read directly from the
// environment (not via viper, which was only ever wired inside the now-
// removed appconfig package) and fails safe to 5.
// No database is required — this exercises the pure resolver.
func TestResolveDefaultMaxSessionsPerUser(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		env  string
		want int
	}{
		{name: "unset falls back to 5", set: false, want: fallbackMaxSessionsPerUser},
		{name: "empty falls back to 5", set: true, env: "", want: fallbackMaxSessionsPerUser},
		{name: "valid positive override is honored", set: true, env: "10", want: 10},
		{name: "one is honored", set: true, env: "1", want: 1},
		{name: "zero falls back to 5", set: true, env: "0", want: fallbackMaxSessionsPerUser},
		{name: "negative falls back to 5", set: true, env: "-3", want: fallbackMaxSessionsPerUser},
		{name: "non-numeric falls back to 5", set: true, env: "abc", want: fallbackMaxSessionsPerUser},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("DEFAULT_MAX_SESSIONS_PER_USER", tc.env)
			} else {
				// Ensure the var is not inherited from the ambient environment.
				t.Setenv("DEFAULT_MAX_SESSIONS_PER_USER", "")
			}
			if got := resolveDefaultMaxSessionsPerUser(); got != tc.want {
				t.Fatalf("resolveDefaultMaxSessionsPerUser() = %d, want %d", got, tc.want)
			}
		})
	}
}
