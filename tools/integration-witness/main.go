package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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
//	integration-witness -check-url   the URL policy only: 0 accepted, 2 refused; dials nothing
//	integration-witness -preflight   reachability only: 0 reachable, 2 not
//	integration-witness              run the profile and judge it
//
// The DSN is IDENTUUM_IDP_TEST_DATABASE_URL and nothing else, and it must pass
// checkTestURL against DEV_PG_HOST_PORT before anything dials or runs
// (OSS-MINT-GUARD-2, review OSS-MINT-ISOLATION M4). Until then the witness fell
// back to IDENTUUM_IDP_DATABASE_URL and then to a 5513 default.

// testEncryptionKey mirrors ci-integration-test's TEST-ONLY default so the
// at-rest suites run here exactly as they do there. Not a secret: it is a
// fixed development value published in the Makefile.
const testEncryptionKey = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

// deps are the witness's only ways out of the process: the environment, the
// preflight's TCP dial and the suite run. Tests replace them, so an entry
// check is proven by counting calls rather than by reaching a server.
type deps struct {
	getenv func(string) string
	dial   func(network, address string, timeout time.Duration) (net.Conn, error)
	suite  func(target string) (out []byte, failed bool)
}

// reachable dials the DSN's host:port. It answers the ONE question the
// preflight asks — is there a server to talk to — without opening a database
// session, so it needs no driver and cannot hang past its own timeout. Its
// caller has already passed the DSN through checkTestURL, so the authority it
// dials is the only endpoint the driver can use.
func reachable(raw string, dial func(network, address string, timeout time.Duration) (net.Conn, error)) (string, error) {
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
	conn, err := dial("tcp", host, 5*time.Second)
	if err != nil {
		return host, err
	}
	_ = conn.Close()
	return host, nil
}

// runSuite runs the integration profile against target and returns its
// combined output.
func runSuite(target string) ([]byte, bool) {
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
	return out, runErr != nil
}

// run is the testable entrypoint; its return value is the process exit code.
func run(args []string, d deps, stdout io.Writer) int {
	fs := flag.NewFlagSet("integration-witness", flag.ContinueOnError)
	fs.SetOutput(stdout)
	checkURL := fs.Bool("check-url", false, "check only that the test URL passes the accepted-URL policy; dials nothing")
	preflight := fs.Bool("preflight", false, "check only that the test database is reachable")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	target, err := selectTarget(d.getenv)
	if err != nil {
		fmt.Fprintf(stdout, "CANNOT-EVALUATE: integration-witness REFUSED — %v; nothing was dialed or run\n", err)
		return VerdictCannotEvaluate.ExitCode()
	}
	if *checkURL {
		fmt.Fprintln(stdout, "check OK: integration-witness test URL names the selected scratch server and a _test database")
		return 0
	}
	host, err := reachable(target, d.dial)
	if err != nil {
		fmt.Fprintf(stdout, "CANNOT-EVALUATE: integration-profile has no database at %s (%v); a missing database is never a pass\n", host, err)
		return VerdictCannotEvaluate.ExitCode()
	}
	if *preflight {
		fmt.Fprintf(stdout, "check OK: integration-preflight database reachable at %s\n", host)
		return 0
	}

	out, failed := d.suite(target)
	// The full output goes to the operator; the record keeps the one line.
	_, _ = stdout.Write(out)

	verdict, _, line := Classify(string(out), failed, host)
	fmt.Fprintln(stdout, line)
	return verdict.ExitCode()
}

func main() {
	os.Exit(run(os.Args[1:], deps{getenv: os.Getenv, dial: net.DialTimeout, suite: runSuite}, os.Stdout))
}
