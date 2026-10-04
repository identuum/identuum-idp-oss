package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0050APIResourcesSoftDelete is a content-level guard: the column,
// the backfill from deleted organizations, the audience index over live rows
// only, and a Down that restores the index and drops the column.
func TestMigration0050APIResourcesSoftDelete(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0050_api_resources_soft_delete.sql")
	if err != nil {
		t.Fatalf("failed to read 0050: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0050 has no Down section")
	}
	for _, want := range []string{
		"ALTER TABLE api_resources ADD COLUMN deleted_at TIMESTAMPTZ",
		"SET deleted_at = o.deleted_at",
		"CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience) WHERE deleted_at IS NULL",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0050 Up lacks %q", want)
		}
	}
	for _, want := range []string{
		"CREATE UNIQUE INDEX uq_api_resources_audience ON api_resources (audience);",
		"ALTER TABLE api_resources DROP COLUMN IF EXISTS deleted_at",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("0050 Down lacks %q", want)
		}
	}
}
