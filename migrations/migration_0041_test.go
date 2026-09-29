package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0041PendingLoginPasswordChange is a content-level guard over
// the D-017 pending kind: Up admits 'password_change' beside the MFA kinds,
// Down removes those rows before restoring the two-kind check.
func TestMigration0041PendingLoginPasswordChange(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0041_pending_login_password_change.sql")
	if err != nil {
		t.Fatalf("failed to read 0041: %v", err)
	}
	body := string(data)
	up, down, ok := strings.Cut(body, "-- +goose Down")
	if !ok {
		t.Fatalf("0041 has no Down section")
	}
	if !strings.Contains(up, `CHECK (kind IN ('enroll', 'verify', 'password_change'))`) {
		t.Errorf("0041 Up does not admit the password_change kind")
	}
	if !strings.Contains(down, `DELETE FROM mfa_pending_login_sessions WHERE kind = 'password_change';`) ||
		!strings.Contains(down, `CHECK (kind IN ('enroll', 'verify'))`) {
		t.Errorf("0041 Down does not remove the new kind's rows and restore the two-kind check")
	}
}
