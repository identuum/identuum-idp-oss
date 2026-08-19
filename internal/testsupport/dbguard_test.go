package testsupport

import (
	"strings"
	"testing"
)

// The DB-backed test harness refuses any DSN whose database name does not end
// in "_test", so a destructive suite (TRUNCATE + setup replay) cannot run
// against a human's live dev database — unless the explicit disposable-DB
// escape is set. Hermetic: no database, no network.
// RULE: TEST-DB-GUARD-1
func TestRequireTestDatabaseRefusesNonTestDSN(t *testing.T) {
	const devDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable"
	const testDSN = "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable"

	// A live dev database (no _test suffix) is REFUSED, and the message names
	// the offending database so the operator can see what was blocked.
	if err := RequireTestDatabase(devDSN); err == nil {
		t.Fatal("dev DSN (identuum_idp_oss) must be REFUSED — it lacks the _test suffix")
	} else if !strings.Contains(err.Error(), "identuum_idp_oss") {
		t.Fatalf("refusal must name the blocked database; got %q", err.Error())
	}

	// A *_test database is accepted.
	if err := RequireTestDatabase(testDSN); err != nil {
		t.Fatalf("_test DSN must be accepted; got %v", err)
	}

	// The keyword DSN form is parsed too.
	if err := RequireTestDatabase("host=127.0.0.1 dbname=identuum_idp_oss sslmode=disable"); err == nil {
		t.Fatal("keyword-form dev DSN must be REFUSED")
	}
	if err := RequireTestDatabase("host=127.0.0.1 dbname=scratch_test sslmode=disable"); err != nil {
		t.Fatalf("keyword-form _test DSN must be accepted; got %v", err)
	}

	// An unnamed target is refused — not provably a test database.
	if err := RequireTestDatabase("postgres://h:5432/?sslmode=disable"); err == nil {
		t.Fatal("a DSN with no database name must be REFUSED")
	}

	// The explicit disposable-DB escape lets a non-_test DSN through.
	t.Setenv(AllowNonTestDBEnv, "1")
	if err := RequireTestDatabase(devDSN); err != nil {
		t.Fatalf("with %s set, any DSN is accepted; got %v", AllowNonTestDBEnv, err)
	}
}
