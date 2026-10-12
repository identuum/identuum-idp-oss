package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0053EmailVerifiedVia is a content-level guard over the
// email_verified_via migration (OSS-0912-C2, owner Q2 (b)): the column is
// nullable (NULL = never proven), holds only the six named ways, carries
// 'legacy' for every row verified before the upgrade and nothing for the
// rest, and is not tied to email_verified by a constraint (a pending invitee
// can prove a mailbox before activation). Down removes exactly what Up added.
// The rows are exercised by migration_0053_integration_test.go.
func TestMigration0053EmailVerifiedVia(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0053_users_email_verified_via.sql")
	if err != nil {
		t.Fatalf("failed to read 0053: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0053 has no Down section")
	}
	for _, want := range []string{
		"ADD COLUMN email_verified_via TEXT NULL",
		"CHECK (email_verified_via IN ('email_link', 'upstream_idp', 'admin_link', 'admin_set', 'setup', 'legacy'))",
		"UPDATE users SET email_verified_via = 'legacy' WHERE email_verified = true",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0053 Up lacks %q", want)
		}
	}
	if strings.Contains(up, "NOT NULL") || strings.Contains(up, "DEFAULT") {
		t.Errorf("0053 Up must leave the column nullable with no default: NULL means never proven")
	}
	if !strings.Contains(down, "DROP COLUMN IF EXISTS email_verified_via") {
		t.Errorf("0053 Down lacks the column drop")
	}
}
