package testdburl

import "testing"

// The hosted exception is bound to the Integration Tests job on a Linux host:
// every one of the five conditions is required, and the operating system is
// never read from the environment. Each refused row lacks exactly one.
func TestHostedNeedsTheJobOnALinuxHost(t *testing.T) {
	job := map[string]string{"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_JOB": "integration", "RUNNER_OS": "Linux"}
	without := func(k, v string) func(string) string {
		return func(name string) string {
			if name == k {
				return v
			}
			return job[name]
		}
	}
	if !hosted(func(k string) string { return job[k] }, "linux") {
		t.Fatal("the Integration Tests job's declaration on a Linux host must be hosted")
	}
	if hosted(func(k string) string { return job[k] }, "darwin") {
		t.Error("the same declaration on macOS must not be hosted: the owner's 5513 lives there")
	}
	for _, c := range []struct{ name, value string }{
		{"CI", ""}, {"CI", "1"}, {"GITHUB_ACTIONS", ""}, {"GITHUB_JOB", ""},
		{"GITHUB_JOB", "verify"}, {"RUNNER_OS", ""}, {"RUNNER_OS", "macOS"},
	} {
		if hosted(without(c.name, c.value), "linux") {
			t.Errorf("%s=%q must not be hosted", c.name, c.value)
		}
	}

	const own = "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable"
	if err := Check(own, OwnerPort, true); err != nil {
		t.Errorf("hosted: the job's own database on 5513 must be accepted; got %v", err)
	}
	if Check(own, OwnerPort, false) == nil {
		t.Error("not hosted: 5513 must be refused, even for the job's own database")
	}
	if Check("postgres://u:dev-u-not-a-secret@127.0.0.1:5513/x_test", OwnerPort, true) == nil {
		t.Error("hosted: another database on 5513 must be refused")
	}
}
