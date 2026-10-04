package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0049DCRClientRegistrationLimits is a content-level guard: one
// row per client, owned by it, NULL-able limit lists, and Down drops the
// table.
func TestMigration0049DCRClientRegistrationLimits(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0049_dcr_client_registration_limits.sql")
	if err != nil {
		t.Fatalf("failed to read 0049: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0049 has no Down section")
	}
	for _, want := range []string{
		"CREATE TABLE dcr_client_registration_limits",
		"UUID        PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE",
		"allowed_grant_types                 TEXT[],",
		"allowed_token_endpoint_auth_methods TEXT[],",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0049 Up lacks %q", want)
		}
	}
	if !strings.Contains(down, "DROP TABLE IF EXISTS dcr_client_registration_limits") {
		t.Errorf("0049 Down must drop the table it created")
	}
}
