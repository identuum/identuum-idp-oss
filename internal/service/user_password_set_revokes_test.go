package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// An admin who sets a user's password ends that user's sessions and refresh
// tokens, as a self-service password change already does. A plain profile
// edit owes no revocation.
func TestRevokeBeforeWrite_PasswordSetRevokes(t *testing.T) {
	target := &domain.User{ID: uuid.New(), Role: domain.RoleOrgUser}
	var gotReason string
	revoke := func(_ context.Context, id uuid.UUID, reason string) error {
		if id != target.ID {
			t.Errorf("revoked %s, want %s", id, target.ID)
		}
		gotReason = reason
		return nil
	}

	pw := "N3w-Passw0rd!x"
	fn := revokeBeforeWrite(target, UpdateUserOptions{Password: &pw}, revoke)
	if fn == nil {
		t.Fatal("setting a password must revoke the user's credentials")
	}
	if err := fn(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotReason != "user_password_set" {
		t.Errorf("reason = %q, want user_password_set", gotReason)
	}

	name := "New Name"
	if fn := revokeBeforeWrite(target, UpdateUserOptions{Name: &name}, revoke); fn != nil {
		t.Error("a name change must not revoke")
	}
}
