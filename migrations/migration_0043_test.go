package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0043SelfRegistration is a content-level guard over D-021's
// one migration: both switches default OFF, the user state is NULL for every
// existing row (only self-registrants carry one), and Down removes exactly
// what Up added.
func TestMigration0043SelfRegistration(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0043_self_registration.sql")
	if err != nil {
		t.Fatalf("failed to read 0043: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0043 has no Down section")
	}
	for _, want := range []string{
		"self_registration_enabled BOOLEAN     NOT NULL DEFAULT false",
		"registration_verify_email  BOOLEAN NOT NULL DEFAULT false",
		"registration_email_domains TEXT[]  NOT NULL DEFAULT '{}'",
		"ADD COLUMN registration_state TEXT\n",
		"CHECK (registration_state IN ('pending_approval', 'active'))",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0043 Up lacks %q", want)
		}
	}
	for _, banned := range []string{"UPDATE ", "DROP ", "ALTER COLUMN"} {
		if strings.Contains(up, banned) {
			t.Errorf("0043 Up must be additive; it contains %q", banned)
		}
	}
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_users_registration_pending",
		"DROP COLUMN IF EXISTS registration_state",
		"DROP COLUMN IF EXISTS registration_email_domains",
		"DROP COLUMN IF EXISTS registration_verify_email",
		"DROP TABLE IF EXISTS instance_settings",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("0043 Down lacks %q", want)
		}
	}
}
