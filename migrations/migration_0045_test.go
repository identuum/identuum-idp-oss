package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0045AudienceGlobalUnique is a content-level guard over H7's one
// migration: the pre-flight refuses duplicates before the index is created, the
// index is unique across the whole table, and Down removes exactly it. The
// pre-flight is executed against rows by the integration test in
// internal/postgres.
func TestMigration0045AudienceGlobalUnique(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0045_api_resources_audience_global_unique.sql")
	if err != nil {
		t.Fatalf("failed to read 0045: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0045 has no Down section")
	}
	pre := strings.Index(up, "RAISE EXCEPTION")
	idx := strings.Index(up, "CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience)")
	if pre < 0 || idx < 0 || pre > idx {
		t.Errorf("0045 Up must refuse duplicates (RAISE EXCEPTION at %d) before it creates the unique index (at %d)", pre, idx)
	}
	for _, banned := range []string{"DELETE ", "UPDATE ", "DROP "} {
		if strings.Contains(up, banned) {
			t.Errorf("0045 Up must not alter or remove rows to make the index fit; it contains %q", banned)
		}
	}
	if !strings.Contains(down, "DROP INDEX IF EXISTS uq_api_resources_audience") {
		t.Errorf("0045 Down must drop the index it added")
	}
}
