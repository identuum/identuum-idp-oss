//go:build integration

package postgres_test

// The DCR initial-access-token consume boundary, asserted against the live
// SQL through the PUBLIC path (the service Consume the /register handler
// calls). The single-use guarantee lives in ONE atomic UPDATE whose active
// predicate and uses_count increment run in the same statement — this test
// pins that a limited-use token never consumes past its limit, a revoked
// token never consumes at all, and every refusal collapses to the ONE
// opaque sentinel. Same FAIL-not-skip posture as the model teeth.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A DCR initial access token consumes atomically within its use limit and
// never after revocation; every refusal — unknown, exhausted, revoked — is
// the one opaque invalid-token error.
// RULE: DCR-IAT-CONSUME-1
func TestLive_DCRIATConsumeBoundary(t *testing.T) {
	pool := modelTeethPool(t)
	repo := postgres.NewPgxDynamicRegistrationTokenRepository(pool)
	svc := service.NewDCRInitialAccessTokenService(nil, repo)
	ctx := context.Background()

	issued := make([]uuid.UUID, 0, 2)
	t.Cleanup(func() {
		for _, id := range issued {
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM dcr_initial_access_tokens WHERE id = $1`, id)
		}
	})

	// 1) Single-use: the first consume succeeds, the second is refused.
	one, err := svc.Issue(ctx, service.IssueOptions{MaxUses: 1, Description: "boundary single-use"})
	if err != nil {
		t.Fatalf("issue single-use IAT: %v", err)
	}
	issued = append(issued, one.TokenID)

	policy, err := svc.Consume(ctx, one.RawIAT)
	if err != nil || policy == nil || policy.TokenID != one.TokenID {
		t.Fatalf("PREMISE FAILED: a fresh single-use IAT must consume once (policy=%v err=%v)", policy, err)
	}
	if _, err := svc.Consume(ctx, one.RawIAT); !errors.Is(err, service.ErrIATInvalid) {
		t.Errorf("a single-use IAT consumed twice: the second consume must be refused with ErrIATInvalid, got %v", err)
	}

	// 2) Revoked: a revoked token never consumes, even with uses remaining.
	two, err := svc.Issue(ctx, service.IssueOptions{MaxUses: 5, Description: "boundary revoked"})
	if err != nil {
		t.Fatalf("issue second IAT: %v", err)
	}
	issued = append(issued, two.TokenID)
	if err := svc.Revoke(ctx, two.TokenID); err != nil {
		t.Fatalf("revoke second IAT: %v", err)
	}
	if _, err := svc.Consume(ctx, two.RawIAT); !errors.Is(err, service.ErrIATInvalid) {
		t.Errorf("a revoked IAT must not consume: want ErrIATInvalid, got %v", err)
	}
	// Idempotent re-revoke stays nil.
	if err := svc.Revoke(ctx, two.TokenID); err != nil {
		t.Errorf("re-revoking a revoked IAT must be idempotent, got %v", err)
	}

	// 3) Opaqueness: an unknown token fails with the SAME sentinel as the
	// exhausted and revoked cases — nothing on the error distinguishes them.
	if _, err := svc.Consume(ctx, "no-such-raw-token"); !errors.Is(err, service.ErrIATInvalid) {
		t.Errorf("an unknown IAT must fail with the same opaque sentinel, got %v", err)
	}
}
