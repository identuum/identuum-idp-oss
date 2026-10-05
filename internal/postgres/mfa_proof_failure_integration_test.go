//go:build integration

package postgres_test

// The proof routes' wrong-code rows against the live SQL (migration 0048): a
// count per user inside the window, another user's rows never counted, the
// sweep dropping only the rows before its cutoff, and the rows going with
// their user.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestMFAProofFailureRepository_CountSweepAndCascade(t *testing.T) {
	pool := modelTeethPool(t)
	ctx := context.Background()
	orgID := seedScratchOrg(t, pool)
	seedUser := func() uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, password_hash, organization_id, role)
			VALUES ($1, $2, 'x', $3::uuid, 'org_user')`,
			id, "pf-"+uuid.NewString()+"@example.test", orgID); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return id
	}
	alice, bob := seedUser(), seedUser()
	repo := postgres.NewPgxMFAProofFailureRepository(pool)

	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, at := range []time.Time{now.Add(-20 * time.Minute), now.Add(-time.Minute), now} {
		if err := repo.RecordProofFailure(ctx, alice, at); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if err := repo.RecordProofFailure(ctx, bob, now); err != nil {
		t.Fatalf("record bob: %v", err)
	}

	// FUNC-M3: the oldest counted miss's time comes back with the count.
	if n, oldest, err := repo.CountProofFailuresSince(ctx, alice, now.Add(-15*time.Minute)); err != nil || n != 2 || !oldest.Equal(now.Add(-time.Minute)) {
		t.Fatalf("alice inside the window = %d, oldest %s, %v; want 2, oldest %s", n, oldest, err, now.Add(-time.Minute))
	}
	if n, _, err := repo.CountProofFailuresSince(ctx, bob, now.Add(-15*time.Minute)); err != nil || n != 1 {
		t.Fatalf("bob = %d, %v; want 1 (alice's rows are not his)", n, err)
	}

	if _, err := repo.DeleteProofFailuresBefore(ctx, now.Add(-15*time.Minute)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n, _, err := repo.CountProofFailuresSince(ctx, alice, now.Add(-time.Hour)); err != nil || n != 2 {
		t.Errorf("alice after the sweep = %d, %v; want the 2 rows inside the window kept", n, err)
	}

	// FUNC-M3: the operator's MFA reset drops one user's misses only.
	if _, err := repo.DeleteProofFailuresForUser(ctx, alice); err != nil {
		t.Fatalf("delete alice's misses: %v", err)
	}
	if n, oldest, err := repo.CountProofFailuresSince(ctx, alice, now.Add(-time.Hour)); err != nil || n != 0 || !oldest.IsZero() {
		t.Errorf("alice after DeleteProofFailuresForUser = %d, %s, %v; want 0 and a zero time", n, oldest, err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, bob); err != nil {
		t.Fatalf("delete bob: %v", err)
	}
	if n, _, err := repo.CountProofFailuresSince(ctx, bob, now.Add(-time.Hour)); err != nil || n != 0 {
		t.Errorf("bob's rows after his deletion = %d, %v; want them gone with him", n, err)
	}
}
