package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0054EmailVerificationsAddress is a content-level guard over the
// verification-address migration (OSS-0912-C2-FIX, review R1): each
// verification row names the address it was mailed to (a SHA-256, never the
// address), and every unused row written before the upgrade, which names
// none, is spent so that it can prove nothing. Down removes the column only.
// The rows are exercised by migration_0054_integration_test.go.
func TestMigration0054EmailVerificationsAddress(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0054_email_verifications_address.sql")
	if err != nil {
		t.Fatalf("failed to read 0054: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0054 has no Down section")
	}
	for _, want := range []string{
		"ALTER TABLE email_verifications ADD COLUMN email_hash VARCHAR(64) NULL",
		"UPDATE email_verifications SET used_at = NOW() WHERE used_at IS NULL AND email_hash IS NULL",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0054 Up lacks %q", want)
		}
	}
	if !strings.Contains(down, "ALTER TABLE email_verifications DROP COLUMN IF EXISTS email_hash") {
		t.Errorf("0054 Down lacks the column drop")
	}
}
