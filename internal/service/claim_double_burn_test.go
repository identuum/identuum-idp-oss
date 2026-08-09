package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// P3-2: ClaimService.ConsumeClaim burns the claim BEFORE creating the
// org_admin, and the comment says that stops "a parallel attempt landing two
// writes". It only does so if the burn REPORTS whether this caller won.
//
// Delete used to discard the command tag, so the second concurrent claimant
// deleted zero rows, saw a nil error, and went on to mint a SECOND org_admin
// for the same one-shot delegation URL. The delete was idempotent — and
// idempotent is the one thing a delete used as a mutex must not be.
func TestClaimRepo_SecondBurnOfSameClaimIsReported(t *testing.T) {
	repo := newFakeClaimRepo()
	ctx := context.Background()

	id := uuid.New()
	repo.byID[id] = &domain.OrganizationClaim{ID: id, TokenHash: "hash-p32"}
	repo.byHash["hash-p32"] = repo.byID[id]

	// CONTROL: the FIRST burn must succeed, or a refusal below would prove
	// only that the row was never there.
	if err := repo.Delete(ctx, id); err != nil {
		t.Fatalf("CONTROL FAILED: the first burn was refused (%v); this test proves nothing "+
			"unless a normal burn succeeds", err)
	}

	// The racing claimant: same claim, already burned.
	err := repo.Delete(ctx, id)
	if err == nil {
		t.Fatal("the SAME claim was burned TWICE and both reported success — the second " +
			"claimant proceeds past the burn-before-write guard and mints a duplicate org_admin")
	}
	if !errors.Is(err, domain.ErrClaimNotFound) {
		t.Errorf("second burn err = %v, want domain.ErrClaimNotFound", err)
	}
}
