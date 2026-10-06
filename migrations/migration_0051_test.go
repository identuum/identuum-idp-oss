package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0051ServiceAccountExpiryDefaultZero is a content-level guard
// (OSS-SA-EXPIRY-2, owner ruling f): the column default becomes 0, nothing
// rewrites a row, and Down restores 365.
func TestMigration0051ServiceAccountExpiryDefaultZero(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0051_service_account_expiry_default_zero.sql")
	if err != nil {
		t.Fatalf("failed to read 0051: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0051 has no Down section")
	}
	if !strings.Contains(up, "ALTER TABLE organizations ALTER COLUMN service_account_expiry_days SET DEFAULT 0") {
		t.Errorf("0051 Up does not set the default to 0")
	}
	if !strings.Contains(down, "ALTER TABLE organizations ALTER COLUMN service_account_expiry_days SET DEFAULT 365") {
		t.Errorf("0051 Down does not restore the default 365")
	}
	// Ruling f: no existing organization row changes.
	for _, stmt := range []string{"UPDATE", "DELETE", "INSERT"} {
		if strings.Contains(strings.ToUpper(up), stmt+" ") {
			t.Errorf("0051 Up contains %s; no existing row may change", stmt)
		}
	}
}
