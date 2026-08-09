package runtime

import (
	"os"
	"testing"
)

// testDBURL is the single gate for the DB-backed runtime tests (P2-24).
//
// Default behaviour is unchanged: no DSN, the test SKIPS, exactly as the six
// former inline t.Skip sites did. The new mode is the point:
//
//	IDENTUUM_IDP_REQUIRE_DB_TESTS=1
//
// turns a missing DSN into a FAILURE. P2-24's finding was that these tests
// skipped in EVERY gate, local and CI, and a skip is green — so the strongest
// tests in the package were decoration. CI now provides an ephemeral Postgres,
// sets both variables, and a lost service container fails the build loudly
// instead of skipping the suite silently.
func testDBURL(t *testing.T) string {
	t.Helper()
	dbURL := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not — " +
				"this gate REQUIRES the DB-backed tests to run; a skip here would be a silent green " +
				"(P2-24). Fix the Postgres service or unset the require flag.")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed runtime test")
	}
	return dbURL
}
