package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0057PendingLoginPasskeyPasswordChange is a content-level guard
// over the passkey proof kind (OSS-G8-PASSKEY-MFA-CARRYOVER): Up admits
// 'password_change_passkey_uv' beside the three kinds and writes no row (no
// existing handle becomes a proof) and requires the proof's client binding
// (OSS-G8-PASSKEY-MFA-R2); Down removes the new kind's rows and the column
// before restoring the three-kind check.
func TestMigration0057PendingLoginPasskeyPasswordChange(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0057_pending_login_passkey_password_change.sql")
	if err != nil {
		t.Fatalf("failed to read 0057: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0057 has no Down section")
	}
	if !strings.Contains(up, `CHECK (kind IN ('enroll', 'verify', 'password_change', 'password_change_passkey_uv'))`) {
		t.Errorf("0057 Up does not admit the password_change_passkey_uv kind")
	}
	// OSS-G8-PASSKEY-MFA-R2: the proof kind carries its client binding, and
	// no other kind does (OSS-G8-BN2: NULL, not merely not 32 bytes).
	if !strings.Contains(up, `ADD COLUMN client_binding BYTEA;`) ||
		!strings.Contains(up, `CHECK (CASE WHEN kind = 'password_change_passkey_uv' THEN client_binding IS NOT NULL AND octet_length(client_binding) = 32 ELSE client_binding IS NULL END)`) {
		t.Errorf("0057 Up does not require a 32-byte client_binding on the passkey proof kind and NULL on every other kind")
	}
	if !strings.Contains(down, `DROP COLUMN client_binding;`) {
		t.Errorf("0057 Down does not drop client_binding")
	}
	for _, banned := range []string{"UPDATE ", "INSERT ", "DELETE "} {
		if strings.Contains(up, banned) {
			t.Errorf("0057 Up carries %q: it must change no row", banned)
		}
	}
	if !strings.Contains(down, `DELETE FROM mfa_pending_login_sessions WHERE kind = 'password_change_passkey_uv';`) ||
		!strings.Contains(down, `CHECK (kind IN ('enroll', 'verify', 'password_change'))`) {
		t.Errorf("0057 Down does not remove the new kind's rows and restore the three-kind check")
	}
}
