package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0044DynamicallyRegistered is a content-level guard over D-026's
// one migration: the marker defaults to false for every row, apps holding a
// registration access token are marked, a marked app loses skip_consent, and
// Down removes exactly the column Up added. The backfill statements are run
// against rows by the integration test in internal/postgres.
func TestMigration0044DynamicallyRegistered(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0044_oauth_clients_dynamically_registered.sql")
	if err != nil {
		t.Fatalf("failed to read 0044: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0044 has no Down section")
	}
	for _, want := range []string{
		"ADD COLUMN dynamically_registered BOOLEAN NOT NULL DEFAULT false",
		"SET dynamically_registered = true",
		"SELECT client_id FROM dcr_client_registration_tokens",
		"SET skip_consent = false",
		"WHERE dynamically_registered AND skip_consent",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0044 Up lacks %q", want)
		}
	}
	if !strings.Contains(down, "DROP COLUMN IF EXISTS dynamically_registered") {
		t.Errorf("0044 Down must drop the column it added")
	}
}
