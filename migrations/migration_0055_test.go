package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0055UsersAdminPasswordSetAt is a content-level guard over the
// admin-set password expiry migration (OSS-0913-B, Q-G2 (a)): the column is
// added NULL with no default and no backfill, so a row written before the
// upgrade never expires. Down removes the column only. The column is exercised
// by internal/postgres/admin_password_set_at_store_integration_test.go.
func TestMigration0055UsersAdminPasswordSetAt(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0055_users_admin_password_set_at.sql")
	if err != nil {
		t.Fatalf("failed to read 0055: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0055 has no Down section")
	}
	if !strings.Contains(up, "ALTER TABLE users ADD COLUMN admin_password_set_at TIMESTAMPTZ NULL;") {
		t.Errorf("0055 Up lacks the nullable column")
	}
	for _, banned := range []string{"DEFAULT", "UPDATE "} {
		if strings.Contains(up, banned) {
			t.Errorf("0055 Up carries %q: existing rows must keep NULL (no expiry)", banned)
		}
	}
	if !strings.Contains(down, "ALTER TABLE users DROP COLUMN IF EXISTS admin_password_set_at") {
		t.Errorf("0055 Down lacks the column drop")
	}
}
