//go:build integration

package postgres_test

// A completed password reset retires every other outstanding reset link of
// the same user, so an older link sent earlier can no longer set a password.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestClaimPasswordReset_RetiresTheUsersOtherLinks(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()

	orgID := uuid.New()
	slug := "prr-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Prr "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	userID := uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, organization_id, role, email_verified) VALUES ($1, $2, 'x', $3, 'org_user', true)`,
		userID, "u-"+slug+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM password_resets WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	older, newer := "older-"+uuid.NewString(), "newer-"+uuid.NewString()
	for _, h := range []string{older, newer} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, NOW() + interval '1 hour', NOW())`,
			userID, h); err != nil {
			t.Fatalf("seed reset: %v", err)
		}
	}

	repo := postgres.NewPgxPasswordResetRepository(pool)
	if _, claimed, err := repo.ClaimPasswordReset(ctx, newer, "hash-1"); err != nil || !claimed {
		t.Fatalf("the newer link must claim, got claimed=%v err=%v", claimed, err)
	}
	if _, claimed, err := repo.ClaimPasswordReset(ctx, older, "hash-2"); err != nil || claimed {
		t.Errorf("after a completed reset the older link must claim nothing, got claimed=%v err=%v", claimed, err)
	}
}
