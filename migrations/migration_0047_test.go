package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0047SessionRelyingParties is a content-level guard: one row per
// (session, client), the rows go with their session, and Down drops the table.
func TestMigration0047SessionRelyingParties(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0047_session_relying_parties.sql")
	if err != nil {
		t.Fatalf("failed to read 0047: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0047 has no Down section")
	}
	for _, want := range []string{
		"CREATE TABLE session_relying_parties",
		"session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE",
		"PRIMARY KEY (session_id, client_id)",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0047 Up lacks %q", want)
		}
	}
	if !strings.Contains(down, "DROP TABLE IF EXISTS session_relying_parties") {
		t.Errorf("0047 Down must drop the table it created")
	}
}
