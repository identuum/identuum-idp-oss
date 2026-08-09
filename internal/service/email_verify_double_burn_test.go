package service

import (
	"context"
	"errors"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// P3-1/P3-2 CLASS, THIRD INSTANCE — the repository CONTRACT.
//
// EmailVerificationService.VerifyEmail reads the row, checks row.IsValid (which
// tests used_at), then calls MarkAsUsed under the comment "Burn-before-write:
// mark the row used BEFORE the email_verified flag is flipped so a parallel
// attempt cannot win the race" — the same sentence shape as the claim service
// in P3-2. With `WHERE token_hash = $1` and the command tag discarded, both
// racers read a valid row, both flipped used_at, and both proceeded.
//
// WHAT THIS PROVES, precisely: that a SECOND burn of an already-burned row is
// refused at the contract — the compare-and-set the fix introduces. It does NOT
// reproduce a true interleaving: the sequential path is already caught upstream
// by row.IsValid, so an end-to-end race needs a barrier the fake does not have.
// The contract is the layer the fix changed. (P3-1's first test made exactly
// this mistake and passed with the fix reverted; this one does not repeat it.)
func TestMarkAsUsed_SecondBurnOfSameTokenIsRefused(t *testing.T) {
	user := newPasswordResetUser(t, "race@example.test")
	user.EmailVerified = false
	users := newFakeUserRepo(user)
	verifs := newFakeEmailVerificationRepo()
	notifier := &fakeVerificationNotifier{}
	svc := NewEmailVerificationService(users, verifs, notifier, audit.NoopService{},
		EmailVerificationServiceOptions{})

	if err := svc.ResendVerification(context.Background(), "race@example.test"); err != nil {
		t.Fatalf("seeding a verification token: %v", err)
	}

	var hash string
	for h := range verifs.rows {
		hash = h
	}
	if hash == "" {
		t.Fatal("CONTROL FAILED: no verification row was seeded; this test proves nothing")
	}

	// CONTROL: the FIRST burn must win, or a refusal below would prove only
	// that the row was unreachable.
	if err := verifs.MarkAsUsed(context.Background(), hash); err != nil {
		t.Fatalf("CONTROL FAILED: the first burn was refused (%v); this test proves nothing "+
			"unless a normal burn succeeds", err)
	}

	err := verifs.MarkAsUsed(context.Background(), hash)
	if err == nil {
		t.Fatal("the SAME verification token was burned TWICE and both reported success — " +
			"the burn-before-write guard does not exclude a parallel attempt")
	}
	if !errors.Is(err, domain.ErrEmailVerificationAlreadyUsed) {
		t.Errorf("second burn err = %v, want domain.ErrEmailVerificationAlreadyUsed", err)
	}
}
