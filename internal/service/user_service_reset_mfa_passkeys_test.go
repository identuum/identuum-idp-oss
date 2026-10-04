package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// H6: an admin MFA reset is how a compromised account is recovered. A passkey
// registered by whoever held the account is a lasting sign-in factor that the
// TOTP reset alone left in place, so the reset removes the user's passkeys too.

type fakePasskeyStore struct {
	byUser  map[uuid.UUID][]*domain.WebAuthnCredential
	deleted []uuid.UUID
	listErr error
	delErr  error
}

func (f *fakePasskeyStore) ListByUser(_ context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	return f.byUser[userID], f.listErr
}

func (f *fakePasskeyStore) Delete(_ context.Context, id uuid.UUID) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestResetMFAForActor_RemovesThePassKeysToo(t *testing.T) {
	ctx := context.Background()
	org := uuid.New()
	target := uuid.New()
	other := uuid.New()
	mine := []*domain.WebAuthnCredential{{ID: uuid.New()}, {ID: uuid.New()}}
	theirs := []*domain.WebAuthnCredential{{ID: uuid.New()}}

	build := func() (*UserService, *fakePasskeyStore, *inMemoryUserRepo) {
		repo := newUserRepo()
		seedMFARow(repo, target, org, domain.RoleOrgUser)
		store := &fakePasskeyStore{byUser: map[uuid.UUID][]*domain.WebAuthnCredential{target: mine, other: theirs}}
		return NewUserService(nil, repo).WithPasskeyStore(store), store, repo
	}

	t.Run("the user's passkeys are removed and nobody else's", func(t *testing.T) {
		svc, store, repo := build()
		if _, err := svc.ResetMFAForActor(ctx, orgAdminActor(org), target); err != nil {
			t.Fatalf("reset: %v", err)
		}
		if repo.rows[target].MFAEnabled {
			t.Error("the TOTP enrolment was not cleared")
		}
		if len(store.deleted) != 2 || store.deleted[0] != mine[0].ID || store.deleted[1] != mine[1].ID {
			t.Errorf("deleted = %v, want exactly the target's two passkeys", store.deleted)
		}
	})

	t.Run("a refused reset removes nothing", func(t *testing.T) {
		svc, store, _ := build()
		if _, err := svc.ResetMFAForActor(ctx, siteAdminActor(), target); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("site admin reset: err=%v, want ErrForbidden", err)
		}
		if len(store.deleted) != 0 {
			t.Errorf("a refused reset removed passkeys: %v", store.deleted)
		}
	})

	t.Run("a store failure is an error, not a half-done success", func(t *testing.T) {
		svc, store, _ := build()
		store.delErr = errors.New("passkey store down")
		if _, err := svc.ResetMFAForActor(ctx, orgAdminActor(org), target); err == nil {
			t.Error("the reset reported success while the passkeys could not be removed")
		}
	})

	t.Run("no passkey store wired: the reset is as before", func(t *testing.T) {
		repo := newUserRepo()
		seedMFARow(repo, target, org, domain.RoleOrgUser)
		if _, err := NewUserService(nil, repo).ResetMFAForActor(ctx, orgAdminActor(org), target); err != nil {
			t.Errorf("reset without a passkey store: %v", err)
		}
	})
}
