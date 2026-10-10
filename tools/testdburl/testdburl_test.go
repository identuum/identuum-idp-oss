package testdburl

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// OwnerPort is refused unconditionally (judge ruling Q-HOSTED (a),
// OSS-MINT-GUARD-4; review OSS-MINT-GUARD-3-PREREVIEW H3). The full local
// Linux imitation of the former hosted job — every marker GitHub Actions sets
// for the Integration Tests job — admits nothing: the policy reads no marker
// and no operating system, so the refusal is the same on every host. Pure:
// no database, no network, no process.
func TestOwnerPortIsRefusedWhateverTheEnvironment(t *testing.T) {
	const own = "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable"
	imitation := map[string]string{
		"DEV_PG_HOST_PORT":   OwnerPort,
		"CI":                 "true",
		"GITHUB_ACTIONS":     "true",
		"GITHUB_JOB":         "integration",
		"RUNNER_OS":          "Linux",
		"RUNNER_ENVIRONMENT": "github-hosted",
		"GITHUB_RUN_ID":      "123",
	}
	read := 0
	getenv := func(k string) string { read++; return imitation[k] }
	err := CheckEnv(own, getenv)
	if err == nil {
		t.Fatal("the full local Linux imitation of the hosted job must not admit 5513")
	}
	if strings.Contains(err.Error(), "dev-u-not-a-secret") {
		t.Fatalf("the refusal must not print the URL; got %q", err.Error())
	}
	if read != 1 {
		t.Errorf("CheckEnv must read DEV_PG_HOST_PORT and nothing else; it read %d variable(s)", read)
	}
	for _, u := range []string{own, "postgres://u:dev-u-not-a-secret@localhost:5513/x_test"} {
		if Check(u, OwnerPort) == nil {
			t.Errorf("Check must refuse port 5513 for every URL")
		}
	}
	if err := Check("postgres://u:dev-u-not-a-secret@127.0.0.1:"+CIPort+"/identuum_idp_oss_test?sslmode=disable", CIPort); err != nil {
		t.Errorf("the CI port is an ordinary scratch port; got %v", err)
	}
}

// The CI workflow publishes every test PostgreSQL service on CIPort and
// selects CIPort as DEV_PG_HOST_PORT; it maps no host port to 5513 or 5432,
// and its readiness wait names no other port.
func TestCIWorkflowUsesTheCIPort(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	wf := string(b)
	maps := regexp.MustCompile(`(?m)^\s*-\s*"?(\d+):5432"?\s*$`).FindAllStringSubmatch(wf, -1)
	if len(maps) == 0 {
		t.Fatal("ci.yml publishes no PostgreSQL service port")
	}
	for _, m := range maps {
		if m[1] != CIPort {
			t.Errorf("ci.yml publishes a PostgreSQL service on host port %s, not %s", m[1], CIPort)
		}
	}
	sel := regexp.MustCompile(`(?m)^\s*DEV_PG_HOST_PORT:\s*"?(\d+)"?\s*$`).FindAllStringSubmatch(wf, -1)
	if len(sel) != len(maps) {
		t.Errorf("ci.yml has %d PostgreSQL service(s) but selects DEV_PG_HOST_PORT %d time(s)", len(maps), len(sel))
	}
	for _, m := range sel {
		if m[1] != CIPort {
			t.Errorf("ci.yml selects DEV_PG_HOST_PORT=%s, not %s", m[1], CIPort)
		}
	}
	for _, m := range regexp.MustCompile(`(127\.0\.0\.1|localhost):(\d+)/|-p (\d+)`).FindAllStringSubmatch(wf, -1) {
		if p := m[2] + m[3]; p != CIPort {
			t.Errorf("ci.yml names PostgreSQL port %s, not %s", p, CIPort)
		}
	}
}
