package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// P3-1: MarkRotated was a blind `UPDATE ... WHERE id = $1` with the result
// discarded, so N concurrent rotations of the same row ALL reported success.
// Each caller inserted a replacement and returned a fresh token; one refresh
// token became N live lineages, and the row's ReplacedBy was simply overwritten
// by whichever writer arrived last.
//
// WHAT THIS TEST PROVES, precisely: that the second rotation of an
// already-rotated row is REFUSED at the repository contract — the
// compare-and-set the fix introduces. It does NOT reproduce a true interleaving
// of two in-flight requests; the sequential path is already caught upstream by
// the ReplacedBy reuse branch, so an end-to-end race needs a barrier the
// in-memory fake does not have. The contract below is the layer the fix changed.
func TestMarkRotated_SecondRotationOfSameRowIsRefused(t *testing.T) {
	repo := newInMemoryRefreshTokenRepo()
	ctx := context.Background()
	now := time.Now().UTC()

	id, first, second := uuid.New(), uuid.New(), uuid.New()
	if err := repo.Insert(ctx, &domain.RefreshToken{
		ID:        id,
		ClientID:  "client-p31",
		Subject:   "user-p31",
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// CONTROL: the FIRST rotation must win, or a refusal below would prove
	// nothing except that the row was unreachable.
	if err := repo.MarkRotated(ctx, id, first, now); err != nil {
		t.Fatalf("CONTROL FAILED: the first rotation was refused (%v); this test proves "+
			"nothing unless a normal rotation succeeds", err)
	}

	// The racing writer: the SAME row, already revoked and linked.
	err := repo.MarkRotated(ctx, id, second, now)
	if err == nil {
		t.Fatal("the SAME refresh row was rotated TWICE and both succeeded — one token " +
			"becomes two live lineages and ReplacedBy is overwritten, so the reuse " +
			"detector never sees the first replacement")
	}
	if !errors.Is(err, repository.ErrRefreshAlreadyRotated) {
		t.Errorf("second rotation err = %v, want repository.ErrRefreshAlreadyRotated", err)
	}
}
