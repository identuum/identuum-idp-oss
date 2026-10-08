package service

import "testing"

// V1-025 (testbook): the service set 10 sessions whenever a create named no
// value, so the operator default DEFAULT_MAX_SESSIONS_PER_USER never applied.
// The configured default applies; unset keeps today's 10; an explicit value
// is kept.
func TestBuildOrganization_MaxSessionsDefault(t *testing.T) {
	opts := func(n int) CreateOrganizationOptions {
		return CreateOrganizationOptions{Name: "Beta", Domain: "beta.example", MaxSessionsPerUser: n}
	}
	cases := []struct {
		name, env string
		explicit  int
		want      int
	}{
		{"the configured default applies", "2", 0, 2},
		{"unset keeps today's 10", "", 0, 10},
		{"a value that is not a positive number keeps 10", "zero", 0, 10},
		{"an explicit value is kept", "2", 7, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFAULT_MAX_SESSIONS_PER_USER", tc.env)
			org, err := buildOrganization(opts(tc.explicit))
			if err != nil {
				t.Fatal(err)
			}
			if org.MaxSessionsPerUser != tc.want {
				t.Fatalf("max sessions per user %d; want %d", org.MaxSessionsPerUser, tc.want)
			}
		})
	}
}
