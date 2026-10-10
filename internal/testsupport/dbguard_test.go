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
	// Every refusal below is judged with the escape explicitly OFF, whatever
	// the caller's environment says.
	t.Setenv(AllowNonTestDBEnv, "")

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

	// The EFFECTIVE database is judged, not the URL path (review
	// OSS-MINT-ISOLATION M2): the driver reads dbname and database from the
	// URL's options, percent-decoded, and they override the path; a service
	// option can name a database the path never shows. Each is refused even
	// when the path ends in _test.
	for _, opt := range []string{
		"dbname=identuum_idp_oss",
		"database=identuum_idp_oss",
		"%64bname=identuum_idp_oss",
		"sslmode=disable&dbname=identuum_idp_oss",
		"dbname=scratch_test&dbname=identuum_idp_oss",
		"service=live",
		"servicefile=/tmp/pg_service.conf",
	} {
		if err := RequireTestDatabase("postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:35599/x_test?" + opt); err == nil {
			t.Errorf("a _test path with the option %q must be REFUSED — the option decides the database", opt)
		}
	}
	// A keyword DSN naming its database twice is refused: which one wins is
	// the driver's choice, not the guard's.
	if err := RequireTestDatabase("host=127.0.0.1 dbname=scratch_test dbname=identuum_idp_oss"); err == nil {
		t.Error("a keyword DSN with two dbname fields must be REFUSED")
	}

	// The explicit disposable-DB escape lets a non-_test DSN through.
	t.Setenv(AllowNonTestDBEnv, "1")
	if err := RequireTestDatabase(devDSN); err != nil {
		t.Fatalf("with %s set, any DSN is accepted; got %v", AllowNonTestDBEnv, err)
	}
}
