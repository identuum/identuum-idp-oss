//go:build integration

package postgres_test

// Q-B2: a completed reset (self-service mail or D9 link) clears
// requires_password_change with the password, in the same transaction
// (ClaimPasswordReset). Today the UPDATE writes password_hash and updated_at
// only (password_reset_repository_pgx.go:131), so an admin-set password
// followed by a reset still asks for a change. Compiles today; RED on the
// flag. Needs PostgreSQL.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestClaimPasswordReset_ClearsRequiredChange(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID, userID := uuid.New(), uuid.New()
	slug := "prc-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Prc "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified, requires_password_change) VALUES ($1, $2, 'x', $3, 'org_user', true, true)`,
		userID, "u-"+slug+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM password_resets WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	hash := "clear-" + uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, NOW() + interval '1 hour', NOW())`, userID, hash); err != nil {
		t.Fatalf("seed reset: %v", err)
	}
	repo := postgres.NewPgxPasswordResetRepository(pool)
	if _, claimed, err := repo.ClaimPasswordReset(ctx, hash, "hash-chosen"); err != nil || !claimed {
		t.Fatalf("claim = %v %v; want claimed", claimed, err)
	}
	var mustChange bool
	if err := pool.QueryRow(ctx, `SELECT requires_password_change FROM users WHERE id = $1`, userID).Scan(&mustChange); err != nil {
		t.Fatalf("read flag: %v", err)
	}
	if mustChange {
		t.Errorf("requires_password_change still true after a completed reset; the member chose this password")
	}
}
