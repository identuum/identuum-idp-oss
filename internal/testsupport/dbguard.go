// Package testsupport holds helpers shared across the DB-backed test suites.
//
// It is imported ONLY from _test.go files, so it never links into the product
// binary; it exists so the "_test database" refusal is one function every
// DB-backed helper funnels through rather than a rule re-implemented per
// package.
package testsupport

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// AllowNonTestDBEnv is the explicit escape hatch: set it (to any non-empty
// value) to run the DB-backed tests against a database whose name does not end
// in "_test" — for a genuinely throwaway/disposable database only.
const AllowNonTestDBEnv = "IDENTUUM_IDP_ALLOW_NON_TEST_DB"

// databaseName extracts the database name from a Postgres DSN, both the URL
// form (postgres://user:pw@host:port/DBNAME?opts) and the keyword form
// (host=… dbname=DBNAME …). Returns "" when it cannot be determined.
func databaseName(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if strings.HasPrefix(trimmed, "postgres://") || strings.HasPrefix(trimmed, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(u.Path, "/")
	}
	// keyword form: find dbname=…
	for _, field := range strings.Fields(trimmed) {
		if name, ok := strings.CutPrefix(field, "dbname="); ok {
			return name
		}
	}
	return ""
}

// RequireTestDatabase refuses any DSN whose database name does not end in
// "_test", unless AllowNonTestDBEnv is set. The DB-backed suites TRUNCATE and
// replay setup; this keeps them off a human's live dev database (the
// TEST-DB-ISOLATION-1 hazard: the integration suite and the dev DB were the
// same database by default). A DSN with no discernible database name is
// refused too — an unnamed target is not provably a test target.
func RequireTestDatabase(dsn string) error {
	if os.Getenv(AllowNonTestDBEnv) != "" {
		return nil
	}
	name := databaseName(dsn)
	if strings.HasSuffix(name, "_test") {
		return nil
	}
	return fmt.Errorf(
		"refusing DB-backed test against database %q: its name must end in %q because these suites TRUNCATE and replay setup. "+
			"Point IDENTUUM_IDP_TEST_DATABASE_URL at a *_test database (e.g. identuum_idp_oss_test), "+
			"or set %s=1 for a genuinely disposable database",
		name, "_test", AllowNonTestDBEnv,
	)
}
