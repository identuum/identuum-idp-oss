// Package testsupport holds helpers shared across the DB-backed test suites.
//
// It is imported ONLY from _test.go files, so it never links into the product
// binary; it exists so the test-database refusal is one function every
// DB-backed helper funnels through rather than a rule re-implemented per
// package.
package testsupport

import (
	"fmt"
	"os"

	"github.com/identuum/identuum-idp-oss/tools/testdburl"
)

// RequireTestDatabase refuses a DSN unless its EFFECTIVE endpoint is a *_test
// database on the selected scratch server: the accepted-URL policy of
// tools/testdburl, judged against DEV_PG_HOST_PORT read from the environment —
// the same policy the Makefile's test-db-endpoint guard and the integration
// witness apply. The DB-backed suites TRUNCATE, replay setup and DROP/CREATE
// scratch databases; this keeps them off a human's live dev database and off
// the owner's PostgreSQL on 5513 (TEST-DB-ISOLATION-1; review
// OSS-MINT-GUARD-2 G1), whichever runner started them, `go test` by hand and
// CI included. A keyword DSN, an option that could pick another host, port or
// database, a server other than 127.0.0.1/localhost on DEV_PG_HOST_PORT, and
// 5513 in any environment (OSS-MINT-GUARD-4, judge ruling Q-HOSTED (a)) are
// all refused. There is no environment escape: the former
// IDENTUUM_IDP_ALLOW_NON_TEST_DB is not consulted.
func RequireTestDatabase(dsn string) error {
	if err := testdburl.CheckEnv(dsn, os.Getenv); err != nil {
		return fmt.Errorf("refusing a DB-backed test: %v (these suites TRUNCATE and replay setup, so they run only against a *_test database on the selected scratch server; set DEV_PG_HOST_PORT to that server's port and point IDENTUUM_IDP_TEST_DATABASE_URL at postgres://...@127.0.0.1:<port>/<name>_test)", err)
	}
	return nil
}
