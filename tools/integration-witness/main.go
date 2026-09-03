package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// integration-witness runs the integration-tagged profile and prints ONE
// evidence line for the gate-witness record (see verdict.go for the ruling
// and the three outcomes).
//
//	integration-witness -preflight   reachability only: 0 reachable, 2 not
//	integration-witness              run the profile and judge it
//
// The DSN comes from IDENTUUM_IDP_TEST_DATABASE_URL, falling back to
// IDENTUUM_IDP_DATABASE_URL, then to the Makefile's OSS_TEST_DB_URL default —
// the same order the harness itself uses.
const defaultTestDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable"

// testEncryptionKey mirrors ci-integration-test's TEST-ONLY default so the
// at-rest suites run here exactly as they do there. Not a secret: it is a
// fixed development value published in the Makefile.
const testEncryptionKey = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

func dsn() string {
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	return defaultTestDSN
}

// reachable dials the DSN's host:port. It answers the ONE question the
// preflight asks — is there a server to talk to — without opening a database
// session, so it needs no driver and cannot hang past its own timeout.
func reachable(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("unparseable DSN: %w", err)
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("DSN carries no host")
	}
	if !strings.Contains(host, ":") {
		host += ":5432"
	}
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return host, err
	}
	_ = conn.Close()
	return host, nil
}

func main() {
	preflight := flag.Bool("preflight", false, "check only that the test database is reachable")
	flag.Parse()

	target := dsn()
	host, err := reachable(target)
	if err != nil {
		fmt.Printf("CANNOT-EVALUATE: integration-profile has no database at %s (%v); a missing database is never a pass\n", host, err)
		os.Exit(VerdictCannotEvaluate.ExitCode())
	}
	if *preflight {
		fmt.Printf("check OK: integration-preflight database reachable at %s\n", host)
		return
	}

	// -p 1 serializes packages: they share the ONE test database and the
	// e2e package truncates tables other packages seed (measured 2026-08-21,
	// recorded in the Makefile).
	//
	// -v is LOAD-BEARING, not noise: without it `go test` prints one `ok`
	// line per package and no per-test lines, so the classifier cannot tell a
	// package that ran a hundred tests from one that ran none — and the
	// vacuous-run guard would fire on every green run. Measured on this
	// tool's first live run, which is exactly the guard doing its job.
	cmd := exec.Command("go", "test", "-tags", "integration", "-p", "1", "./...", "-count=1", "-v")
	cmd.Env = append(os.Environ(),
		"IDENTUUM_IDP_TEST_DATABASE_URL="+target,
	)
	if strings.TrimSpace(os.Getenv("IDENTUUM_IDP_ENCRYPTION_KEY")) == "" {
		cmd.Env = append(cmd.Env, "IDENTUUM_IDP_ENCRYPTION_KEY="+testEncryptionKey)
	}
	out, runErr := cmd.CombinedOutput()
	// The full output goes to the operator; the record keeps the one line.
	os.Stdout.Write(out)

	verdict, _, line := Classify(string(out), runErr != nil)
	fmt.Println(line)
	os.Exit(verdict.ExitCode())
}
