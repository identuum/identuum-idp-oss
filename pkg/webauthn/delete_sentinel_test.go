package webauthn_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	pkgwebauthn "github.com/identuum/identuum-idp-oss/pkg/webauthn"
)

// fakeCredRepoForSeam is the smallest CredentialRepository a seam test
// can drive DeleteCredential through: an in-memory slice, ListByUser
// filtered by user, Delete by id. Every other method answers an error so
// no path this test does not exercise can pass by accident.
type fakeCredRepoForSeam struct {
	rows []*pkgwebauthn.Credential
}

func (f *fakeCredRepoForSeam) Create(_ context.Context, _ *pkgwebauthn.Credential) (*pkgwebauthn.Credential, error) {
	return nil, errors.New("fakeCredRepoForSeam: Create not implemented")
}

func (f *fakeCredRepoForSeam) GetByCredentialID(_ context.Context, _ []byte) (*pkgwebauthn.Credential, error) {
	return nil, errors.New("fakeCredRepoForSeam: GetByCredentialID not implemented")
}

func (f *fakeCredRepoForSeam) ListByUser(_ context.Context, userID uuid.UUID) ([]*pkgwebauthn.Credential, error) {
	var out []*pkgwebauthn.Credential
	for _, c := range f.rows {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeCredRepoForSeam) UpdateSignCount(_ context.Context, _ uuid.UUID, _ uint32) error {
	return errors.New("fakeCredRepoForSeam: UpdateSignCount not implemented")
}

func (f *fakeCredRepoForSeam) UpdateLastUsed(_ context.Context, _ uuid.UUID) error {
	return errors.New("fakeCredRepoForSeam: UpdateLastUsed not implemented")
}

func (f *fakeCredRepoForSeam) Delete(_ context.Context, id uuid.UUID) error {
	kept := f.rows[:0]
	for _, c := range f.rows {
		if c.ID != id {
			kept = append(kept, c)
		}
	}
	f.rows = kept
	return nil
}

func (f *fakeCredRepoForSeam) UpdateCloneWarning(_ context.Context, _ uuid.UUID, _ bool) error {
	return errors.New("fakeCredRepoForSeam: UpdateCloneWarning not implemented")
}

// TestPkgSeam_DeleteCredential_RefusesUnownedAndUnknownAsNotYours drives
// Service.DeleteCredential through the public seam only and pins the
// refusal a caller can name: an id that belongs to another user and an id
// that belongs to nobody both come back errors.Is ErrCredentialNotYours,
// deliberately indistinguishable from each other (no existence oracle),
// and distinct from ErrCredentialNotFound (the repository's sentinel for
// a raw credential id with no live row, which this path never returns).
// The refused rows survive; the owner's own delete still works.
func TestPkgSeam_DeleteCredential_RefusesUnownedAndUnknownAsNotYours(t *testing.T) {
	ctx := context.Background()
	owner := uuid.New()
	stranger := uuid.New()
	cred := &pkgwebauthn.Credential{
		ID:             uuid.New(),
		UserID:         owner,
		OrganizationID: uuid.New(),
		CredentialID:   []byte{0x01},
		PublicKey:      []byte{0x02},
	}
	repo := &fakeCredRepoForSeam{rows: []*pkgwebauthn.Credential{cred}}
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceConfig{
		BaseURL:     "https://idp.example.invalid",
		UserRepo:    fakeUserRepoForSeam{},
		CredRepo:    repo,
		SessionRepo: pkgwebauthn.NewInMemorySessionRepository(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// Foreign id: the row exists, the caller does not own it.
	errForeign := svc.DeleteCredential(ctx, stranger, cred.ID)
	if !errors.Is(errForeign, pkgwebauthn.ErrCredentialNotYours) {
		t.Fatalf("foreign-id delete: err = %v, want errors.Is ErrCredentialNotYours", errForeign)
	}
	// Unknown id: no row at all.
	errUnknown := svc.DeleteCredential(ctx, owner, uuid.New())
	if !errors.Is(errUnknown, pkgwebauthn.ErrCredentialNotYours) {
		t.Fatalf("unknown-id delete: err = %v, want errors.Is ErrCredentialNotYours", errUnknown)
	}
	// Deliberately indistinguishable: the same sentinel, the same text.
	if !errors.Is(errForeign, errUnknown) || errForeign.Error() != errUnknown.Error() {
		t.Errorf("foreign (%v) and unknown (%v) refusals differ; they must be indistinguishable to a caller", errForeign, errUnknown)
	}
	// Distinct from the repository's not-found sentinel.
	if errors.Is(errForeign, pkgwebauthn.ErrCredentialNotFound) {
		t.Errorf("the delete refusal must not collapse onto ErrCredentialNotFound (GetByCredentialID's sentinel)")
	}
	// Nothing was removed by a refusal.
	if got, _ := repo.ListByUser(ctx, owner); len(got) != 1 || got[0].ID != cred.ID {
		t.Fatalf("the owner's credential did not survive the refused deletes: %v", got)
	}
	// The owner's own delete still works.
	if err := svc.DeleteCredential(ctx, owner, cred.ID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if got, _ := repo.ListByUser(ctx, owner); len(got) != 0 {
		t.Fatalf("the owner's credential survived its own delete: %v", got)
	}
}
