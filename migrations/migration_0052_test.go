package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0052PKCERequired is a content-level guard over the per-client
// PKCE setting's one migration: every row, existing and new, is pkce_required
// true and the column is NOT NULL; only a public client may be false; Down
// removes exactly what Up added. Rows are exercised by the integration test in
// internal/postgres.
func TestMigration0052PKCERequired(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0052_oauth_clients_pkce_required.sql")
	if err != nil {
		t.Fatalf("failed to read 0052: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0052 has no Down section")
	}
	for _, want := range []string{
		"ADD COLUMN pkce_required BOOLEAN NOT NULL DEFAULT true",
		"CHECK (pkce_required OR is_public)",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0052 Up lacks %q", want)
		}
	}
	if strings.Contains(up, "UPDATE ") || strings.Contains(up, "DEFAULT false") {
		t.Errorf("0052 Up must not turn PKCE off for any row")
	}
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS oauth_clients_pkce_opt_out_public_only",
		"DROP COLUMN IF EXISTS pkce_required",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("0052 Down lacks %q", want)
		}
	}
}
