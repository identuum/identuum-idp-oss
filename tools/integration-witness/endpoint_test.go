package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// endpointCase is ONE row of the accepted-URL policy, shared by the witness
// and the Makefile's test-db-endpoint guard: the same table is run through
// both, so the two implementations cannot drift apart unnoticed. The selected
// scratch port is 35599 unless the row says otherwise; jobMarkers rows set
// every marker GitHub Actions sets for the Integration Tests job (CI=true,
// GITHUB_ACTIONS=true, GITHUB_JOB=integration, RUNNER_OS=Linux), the full
// local Linux imitation of the former hosted exception. No marker changes a
// verdict on any host: 5513 is refused everywhere (judge ruling Q-HOSTED (a),
// OSS-MINT-GUARD-4).
type endpointCase struct {
	label      string
	url        string
	port       string
	jobMarkers bool
	accept     bool
	// dialed is the host:port an accepted row's preflight must dial.
	dialed string
}

const scratch = "35599"

// Every credential below is fake by construction (credential-transparency).
func endpointCases() []endpointCase {
	base := "postgres://u:dev-u-not-a-secret@127.0.0.1:35599/x_test"
	return []endpointCase{
		// Accepted: one literal loopback host on the selected port, a plain
		// *_test database, and at most the sslmode option.
		{label: "loopback, sslmode", url: base + "?sslmode=disable", port: scratch, accept: true, dialed: "127.0.0.1:35599"},
		{label: "loopback, no options", url: base, port: scratch, accept: true, dialed: "127.0.0.1:35599"},
		{label: "localhost, postgresql scheme", url: "postgresql://u:dev-u-not-a-secret@localhost:35599/scratch_test?sslmode=require", port: scratch, accept: true, dialed: "localhost:35599"},
		{label: "no userinfo", url: "postgres://127.0.0.1:35599/x_test", port: scratch, accept: true, dialed: "127.0.0.1:35599"},
		{label: "CI job: its own database on the CI port", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:45432/identuum_idp_oss_test?sslmode=disable", port: "45432", jobMarkers: true, accept: true, dialed: "127.0.0.1:45432"},

		// M1 (review E3/E4): a connection option overrides the checked authority.
		{label: "port option", url: base + "?port=5513", port: scratch},
		{label: "host and port options", url: base + "?host=127.0.0.1&port=5513", port: scratch},
		{label: "another host by option", url: base + "?host=db.example&port=5513", port: scratch},
		{label: "socket directory by option", url: base + "?host=%2Ftmp&port=5513", port: scratch},
		{label: "percent-encoded port key", url: base + "?%70ort=5513", port: scratch},
		{label: "percent-encoded host key", url: base + "?%68ost=db.example", port: scratch},
		{label: "multi-host option list", url: base + "?host=127.0.0.1,127.0.0.1&port=35599,5513", port: scratch},
		{label: "multi-host authority", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:35599,127.0.0.1:5513/x_test", port: scratch},
		{label: "hostaddr option", url: base + "?hostaddr=10.0.0.1", port: scratch},
		{label: "service option", url: base + "?service=live", port: scratch},
		{label: "servicefile option", url: base + "?servicefile=/tmp/pg_service.conf", port: scratch},
		{label: "percent-encoded service key", url: base + "?%73ervice=live", port: scratch},
		{label: "sslmode then port", url: base + "?sslmode=disable&port=5513", port: scratch},
		{label: "socket authority", url: "postgres://u:dev-u-not-a-secret@%2Ftmp:35599/x_test", port: scratch},
		{label: "fragment", url: base + "#x", port: scratch},

		// M2: the effective database differs from the path, or is not *_test.
		{label: "dbname option", url: base + "?dbname=identuum_idp_oss", port: scratch},
		{label: "database option", url: base + "?database=identuum_idp_oss", port: scratch},
		{label: "percent-encoded dbname key", url: base + "?%64bname=identuum_idp_oss", port: scratch},
		{label: "non-test database", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:35599/identuum_idp_oss", port: scratch},
		{label: "percent-encoded database name", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:35599/x%5Ftest", port: scratch},
		{label: "no database", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:35599/", port: scratch},

		// The authority itself.
		{label: "other port", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/x_test", port: scratch},
		{label: "non-loopback host", url: "postgres://u:dev-u-not-a-secret@db.example:35599/x_test", port: scratch},
		{label: "wildcard address", url: "postgres://u:dev-u-not-a-secret@0.0.0.0:35599/x_test", port: scratch},
		{label: "IPv6 loopback", url: "postgres://u:dev-u-not-a-secret@[::1]:35599/x_test", port: scratch},
		{label: "no port (5432)", url: "postgres://u:dev-u-not-a-secret@localhost/x_test", port: scratch},
		{label: "userinfo hiding a query", url: "postgres://u?x@127.0.0.1:35599/x_test", port: scratch},
		{label: "upper-case scheme", url: "POSTGRES://u:dev-u-not-a-secret@127.0.0.1:35599/x_test", port: scratch},
		{label: "keyword DSN", url: "host=127.0.0.1 port=35599 dbname=x_test", port: scratch},

		// Q-HOSTED (a): 5513 is the owner's server and no environment admits
		// it, the full local Linux imitation of the former hosted job included.
		{label: "5513 locally", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test", port: "5513"},
		{label: "the full local Linux imitation of the hosted job on 5513", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable", port: "5513", jobMarkers: true},
		{label: "the job's markers, another database on 5513", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:5513/x_test", port: "5513", jobMarkers: true},
		{label: "no port selected", url: base, port: ""},
		{label: "port not a number", url: base, port: "35599x"},
		{label: "port out of range", url: "postgres://u:dev-u-not-a-secret@127.0.0.1:70000/x_test", port: "70000"},
	}
}

func caseEnv(c endpointCase) map[string]string {
	env := map[string]string{"IDENTUUM_IDP_TEST_DATABASE_URL": c.url, "DEV_PG_HOST_PORT": c.port}
	if c.jobMarkers {
		env["CI"], env["GITHUB_ACTIONS"] = "true", "true"
		env["GITHUB_JOB"], env["RUNNER_OS"] = "integration", "Linux"
	}
	return env
}

// accepted is a row's verdict, the same on every host.
func (c endpointCase) accepted() bool {
	return c.accept
}

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

// counted is a witness whose every way out is counted and goes nowhere.
type counted struct {
	dials, suites int
	dialed        string
}

func (c *counted) deps(env map[string]string) deps {
	return deps{
		getenv: func(k string) string { return env[k] },
		dial: func(_, address string, _ time.Duration) (net.Conn, error) {
			c.dials++
			c.dialed = address
			return fakeConn{}, nil
		},
		suite: func(string) ([]byte, bool) {
			c.suites++
			return []byte("=== RUN   TestX\n--- PASS: TestX (0.00s)\nok  \tx\t0.1s\n"), false
		},
	}
}

// The witness accepts only an explicit test URL that names the selected
// scratch endpoint and a *_test database, and refuses every other form before
// it dials or runs a suite. Labels and counters only: a failure never prints
// a URL.
// RULE: WITNESS-EXPLICIT-DB-1
func TestRule_WITNESS_EXPLICIT_DB_1(t *testing.T) {
	for _, c := range endpointCases() {
		for _, mode := range [][]string{{"-check-url"}, {"-preflight"}, nil} {
			var w counted
			var out bytes.Buffer
			code := run(mode, w.deps(caseEnv(c)), &out)
			name := c.label + " " + strings.Join(append([]string{"mode"}, mode...), " ")
			if c.accepted() && len(mode) == 1 && mode[0] == "-check-url" {
				if code != 0 || w.dials != 0 || w.suites != 0 {
					t.Errorf("%s: want accepted with no dial and no suite; got exit %d, %d dial(s), %d suite run(s)", name, code, w.dials, w.suites)
				}
				continue
			}
			if c.accepted() {
				if code != 0 || w.dials != 1 || w.dialed != c.dialed {
					t.Errorf("%s: want accepted and one dial to %s; got exit %d, %d dial(s) to the expected endpoint=%v", name, c.dialed, code, w.dials, w.dialed == c.dialed)
				}
				continue
			}
			if code != VerdictCannotEvaluate.ExitCode() || w.dials != 0 || w.suites != 0 {
				t.Errorf("%s: want refused (exit 2) with no dial and no suite; got exit %d, %d dial(s), %d suite run(s)", name, code, w.dials, w.suites)
			}
		}
	}

	// No explicit test URL: no 5513 default and no development-URL fallback.
	for label, env := range map[string]map[string]string{
		"nothing set":              {},
		"only the scratch port":    {"DEV_PG_HOST_PORT": scratch},
		"only the development URL": {"DEV_PG_HOST_PORT": scratch, "IDENTUUM_IDP_DATABASE_URL": "postgres://u:dev-u-not-a-secret@127.0.0.1:35599/x_test"},
	} {
		var w counted
		var out bytes.Buffer
		if code := run([]string{"-preflight"}, w.deps(env), &out); code != 2 || w.dials != 0 {
			t.Errorf("%s: want refused with no dial; got exit %d, %d dial(s)", label, code, w.dials)
		}
	}
}

// The Makefile's test-db-endpoint guard, the prerequisite of every DB-backed
// make target, judges the same table the same way, refusing with exit 2 before
// any command. It is run for real (it calls nothing but the shell), from the
// repository root, with only the case's variables set.
// RULE: TEST-DB-ENDPOINT-1
func TestRule_TEST_DB_ENDPOINT_1(t *testing.T) {
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Fatalf("make is required to judge the Makefile guard: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range endpointCases() {
		cmd := exec.Command(makeBin, "--no-print-directory", "-s", "test-db-endpoint")
		cmd.Dir = root
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_OPTIONAL_LOCKS=0"}
		for k, v := range caseEnv(c) {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		out, runErr := cmd.CombinedOutput()
		code := 0
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			code = exitErr.ExitCode()
		} else if runErr != nil {
			t.Fatalf("%s: make did not run: %v", c.label, runErr)
		}
		refused := strings.Contains(string(out), "test-db-endpoint: REFUSED")
		if c.accepted() && (code != 0 || refused) {
			t.Errorf("%s: the Makefile guard refused an accepted URL (exit %d)", c.label, code)
		}
		if !c.accepted() && (code != 2 || !refused) {
			t.Errorf("%s: the Makefile guard accepted a refused URL (exit %d, refusal line %v)", c.label, code, refused)
		}
		if strings.Contains(string(out), "dev-u-not-a-secret") {
			t.Errorf("%s: the guard printed the URL's userinfo", c.label)
		}
	}
}
