package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// toSafeUser is the user wire-contract projection: it carries the safe fields
// (id, email, role, ...) and NEVER the password hash, MFA secret, MFA recovery
// codes, or the activation/verification token hashes. A nil user maps to the
// zero projection.
// RULE: WIRE-CONTRACT-USER-1
func TestToSafeUser_NeverLeaksSecretMaterial(t *testing.T) {
	sec := "TOTP-SECRET-XYZ"
	act := "ACTIVATION-HASH-XYZ"
	ver := "VERIFICATION-HASH-XYZ"
	u := &domain.User{
		ID:                    uuid.New(),
		Email:                 "u@example.test",
		Role:                  domain.RoleOrgUser,
		PasswordHash:          "$argon2id$PW-SECRET-XYZ",
		MFASecret:             &sec,
		MFARecoveryCodes:      []string{"RECOVERY-CODE-XYZ"},
		ActivationTokenHash:   &act,
		VerificationTokenHash: &ver,
	}

	b, err := json.Marshal(toSafeUser(u))
	if err != nil {
		t.Fatalf("marshal safeUser: %v", err)
	}
	s := string(b)
	for _, secret := range []string{
		"PW-SECRET-XYZ", "TOTP-SECRET-XYZ", "RECOVERY-CODE-XYZ",
		"ACTIVATION-HASH-XYZ", "VERIFICATION-HASH-XYZ",
		"password_hash", "mfa_secret", "recovery",
	} {
		if strings.Contains(s, secret) {
			t.Errorf("safeUser leaked secret material %q in %s", secret, s)
		}
	}
	if !strings.Contains(s, "u@example.test") {
		t.Errorf("safeUser must carry the email; got %s", s)
	}

	// A nil user maps to the zero projection (no panic).
	if got := toSafeUser(nil); got.ID != uuid.Nil {
		t.Errorf("toSafeUser(nil) must be the zero projection, got %+v", got)
	}
}
