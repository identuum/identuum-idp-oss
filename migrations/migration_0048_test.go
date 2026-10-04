package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0048MFAProofFailures is a content-level guard: one row per wrong
// code, owned by its user, indexed for the per-user window count and the
// sweep, and Down drops the table.
func TestMigration0048MFAProofFailures(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0048_mfa_proof_failures.sql")
	if err != nil {
		t.Fatalf("failed to read 0048: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0048 has no Down section")
	}
	for _, want := range []string{
		"CREATE TABLE mfa_proof_failures",
		"user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE",
		"ON mfa_proof_failures (user_id, failed_at)",
		"ON mfa_proof_failures (failed_at)",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0048 Up lacks %q", want)
		}
	}
	if !strings.Contains(down, "DROP TABLE IF EXISTS mfa_proof_failures") {
		t.Errorf("0048 Down must drop the table it created")
	}
}
