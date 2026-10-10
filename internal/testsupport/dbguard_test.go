package testsupport

import (
	"strings"
	"testing"
)

// The DB-backed test harness judges the EFFECTIVE endpoint of a test database
// URL with the same policy as the Makefile's test-db-endpoint guard and the
// integration witness (review OSS-MINT-GUARD-2 G1): a destructive suite
// (TRUNCATE + setup replay, DROP/CREATE DATABASE) never reaches the owner's
// PostgreSQL on 5513, another server, or a database not ending in _test, and
// no environment escape admits one. Hermetic: no database, no network.
// RULE: TEST-DB-GUARD-1
func TestRequireTestDatabaseRefusesNonTestDSN(t *testing.T) {
	const scratchDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:35599/identuum_idp_oss_test?sslmode=disable"
	const devDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:35599/identuum_idp_oss?sslmode=disable"
	const ownerTestDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable"
	// Every case runs with the scratch port selected, whatever the caller's
	// environment says.
	t.Setenv("DEV_PG_HOST_PORT", "35599")

	// A *_test database on the selected loopback port is accepted.
	if err := RequireTestDatabase(scratchDSN); err != nil {
		t.Fatalf("a _test database on 127.0.0.1:35599 must be accepted; got %v", err)
	}

	// A live dev database (no _test suffix) is REFUSED, and the message names
	// the rule, never the URL.
	if err := RequireTestDatabase(devDSN); err == nil {
		t.Fatal("a non-_test database must be REFUSED")
	} else if strings.Contains(err.Error(), "dev-idp_oss_user-not-a-secret") {
		t.Fatalf("the refusal must not print the URL; got %q", err.Error())
	}

	// The keyword DSN form is not read, so it is refused whatever it names.
	for _, dsn := range []string{
		"host=127.0.0.1 port=35599 dbname=identuum_idp_oss sslmode=disable",
		"host=127.0.0.1 port=35599 dbname=scratch_test sslmode=disable",
	} {
		if err := RequireTestDatabase(dsn); err == nil {
			t.Errorf("a keyword DSN must be REFUSED: its server cannot be checked (%q)", dsn)
		}
	}

	// An unnamed target is refused — not provably a test database.
	if err := RequireTestDatabase("postgres://127.0.0.1:35599/?sslmode=disable"); err == nil {
		t.Fatal("a DSN with no database name must be REFUSED")
	}

	// The EFFECTIVE endpoint is judged, not the authority and path (review
	// OSS-MINT-ISOLATION M1/M2, OSS-MINT-GUARD-2 G1): the driver reads host,
	// port, dbname, database and service from the URL's options,
	// percent-decoded, and they override the authority and path. Each is
	// refused even when the path ends in _test.
	for _, opt := range []string{
		"port=5513",
		"host=127.0.0.1&port=5513",
		"%70ort=5513",
		"dbname=identuum_idp_oss",
		"database=identuum_idp_oss",
		"%64bname=identuum_idp_oss",
		"sslmode=disable&dbname=identuum_idp_oss",
		"dbname=scratch_test&dbname=identuum_idp_oss",
		"service=live",
		"servicefile=/tmp/pg_service.conf",
	} {
		if err := RequireTestDatabase("postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:35599/x_test?" + opt); err == nil {
			t.Errorf("a _test path with the option %q must be REFUSED — the option decides the endpoint", opt)
		}
	}

	// The server: another host, another port than the selected one, and the
	// owner's 5513 even for a _test database, are refused everywhere.
	for label, dsn := range map[string]string{
		"a non-loopback host":            "postgres://u:dev-u-not-a-secret@db.example:35599/x_test",
		"a port other than the selected": "postgres://u:dev-u-not-a-secret@127.0.0.1:35600/x_test",
	} {
		if err := RequireTestDatabase(dsn); err == nil {
			t.Errorf("%s must be REFUSED", label)
		}
	}
	t.Setenv("DEV_PG_HOST_PORT", "5513")
	if err := RequireTestDatabase(ownerTestDSN); err == nil {
		t.Error("the owner's 5513 must be REFUSED, even for identuum_idp_oss_test")
	}
	// The full local Linux imitation of the former hosted Integration Tests
	// job (judge ruling Q-HOSTED (a), OSS-MINT-GUARD-4): every marker GitHub
	// Actions sets for that job admits nothing either.
	for k, v := range map[string]string{"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_JOB": "integration", "RUNNER_OS": "Linux"} {
		t.Setenv(k, v)
	}
	if err := RequireTestDatabase(ownerTestDSN); err == nil {
		t.Error("the full hosted-job declaration must not admit 5513")
	}
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITHUB_JOB", "RUNNER_OS"} {
		t.Setenv(k, "")
	}

	// No selected port: nothing to judge the server against, so refused.
	t.Setenv("DEV_PG_HOST_PORT", "")
	if err := RequireTestDatabase(scratchDSN); err == nil {
		t.Error("with DEV_PG_HOST_PORT unset the server cannot be judged, so the DSN must be REFUSED")
	}
	t.Setenv("DEV_PG_HOST_PORT", "35599")

	// The former disposable-database escape admits nothing any more.
	t.Setenv("IDENTUUM_IDP_ALLOW_NON_TEST_DB", "1")
	if err := RequireTestDatabase(devDSN); err == nil {
		t.Error("IDENTUUM_IDP_ALLOW_NON_TEST_DB must not admit a non-_test database")
	}
	t.Setenv("DEV_PG_HOST_PORT", "5513")
	if err := RequireTestDatabase(ownerTestDSN); err == nil {
		t.Error("IDENTUUM_IDP_ALLOW_NON_TEST_DB must not admit the owner's 5513")
	}
}
