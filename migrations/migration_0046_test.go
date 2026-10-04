package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0046GrantTypes is a content-level guard: the column is nullable
// (NULL is unrestricted, so no existing app changes), only the three grant types
// the token endpoint serves can be stored, nothing is backfilled, and Down removes
// what Up added.
func TestMigration0046GrantTypes(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0046_oauth_clients_grant_types.sql")
	if err != nil {
		t.Fatalf("failed to read 0046: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0046 has no Down section")
	}
	for _, want := range []string{
		"ADD COLUMN grant_types TEXT[];",
		"CHECK (grant_types IS NULL OR grant_types <@ ARRAY['authorization_code', 'refresh_token', 'client_credentials']::text[])",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0046 Up lacks %q", want)
		}
	}
	if strings.Contains(up, "UPDATE oauth_clients") {
		t.Errorf("0046 must not backfill: the grant types an earlier registration asked for were never stored")
	}
	for _, want := range []string{"DROP CONSTRAINT IF EXISTS oauth_clients_grant_types_known", "DROP COLUMN IF EXISTS grant_types"} {
		if !strings.Contains(down, want) {
			t.Errorf("0046 Down lacks %q", want)
		}
	}
}
