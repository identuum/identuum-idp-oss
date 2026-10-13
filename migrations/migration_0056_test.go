package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0056UsersEmailGlobalUnique is a content-level guard over the
// one-address-one-account migration (EMAIL-GLOBAL-UNIQUE-1): a duplicate among
// live accounts is refused with SQLSTATE IDM01 before the index is built, the
// index is on lower(email) for live rows only, and Up writes no row (no
// UPDATE, no DELETE: a refused upgrade changes nothing). Down drops the index
// only. The refusal and the index are exercised by
// pkg/runtime/email_global_migration_test.go.
func TestMigration0056UsersEmailGlobalUnique(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0056_users_email_global_unique.sql")
	if err != nil {
		t.Fatalf("failed to read 0056: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0056 has no Down section")
	}
	for _, want := range []string{
		"ERRCODE = 'IDM01'",
		"GROUP BY lower(email) HAVING count(*) > 1",
		"CREATE UNIQUE INDEX users_email_lower_key_undeleted\n    ON users (lower(email)) WHERE deleted_at IS NULL;",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0056 Up lacks %q", want)
		}
	}
	if strings.Index(up, "RAISE EXCEPTION") > strings.Index(up, "CREATE UNIQUE INDEX") {
		t.Errorf("0056 Up must refuse before it builds the index")
	}
	for _, banned := range []string{"UPDATE ", "DELETE ", "NO TRANSACTION"} {
		if strings.Contains(up, banned) {
			t.Errorf("0056 Up carries %q: it must change no row and run in one transaction", banned)
		}
	}
	if !strings.Contains(down, "DROP INDEX IF EXISTS users_email_lower_key_undeleted") {
		t.Errorf("0056 Down lacks the index drop")
	}
}
