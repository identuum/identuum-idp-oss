//go:build integration

package postgres_test

// D9 and Q-B2 at the store. (1) Issuing an administrator's link
// (CreateRetiringOthers) marks the user's earlier unused links used in the
// same transaction, so only the newest link can set a password. (2) A
// completed reset clears requires_password_change with the password: the
// member chose it, so no change is owed at the next sign-in.
//
// (1) does not compile until the slice adds CreateRetiringOthers (red at
// vet); (2) compiles today and fails on the flag. Needs PostgreSQL.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedResetUser(t *testing.T, mustChange bool) (context.Context, *postgres.PgxPasswordResetRepository, uuid.UUID, func(string) bool) {
	t.Helper()
	pool := keyEncPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	orgID, userID := uuid.New(), uuid.New()
	slug := "prl-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "Prl "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified, requires_password_change) VALUES ($1, $2, 'x', $3, 'org_user', true, $4)`,
		userID, "u-"+slug+"@example.test", orgID, mustChange); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM password_resets WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	flag := func(string) bool {
		var v bool
		if err := pool.QueryRow(ctx, `SELECT requires_password_change FROM users WHERE id = $1`, userID).Scan(&v); err != nil {
			t.Fatalf("read flag: %v", err)
		}
		return v
	}
	return ctx, postgres.NewPgxPasswordResetRepository(pool), userID, flag
}

// RULE: D9-LINK-RETIRE-PGX-1
func TestCreateRetiringOthers_OnlyTheNewestLinkWorks(t *testing.T) {
	ctx, repo, userID, _ := seedResetUser(t, false)
	now := time.Now().UTC()
	older, newer := "older-"+uuid.NewString(), "newer-"+uuid.NewString()
	for _, h := range []string{older, newer} {
		if err := repo.CreateRetiringOthers(ctx, &domain.PasswordReset{UserID: userID, TokenHash: h, ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
			t.Fatalf("issue link: %v", err)
		}
	}
	if _, claimed, err := repo.ClaimPasswordReset(ctx, older, "hash-old"); err != nil || claimed {
		t.Errorf("the earlier link still claims after a newer one was issued (claimed=%v err=%v)", claimed, err)
	}
	if _, claimed, err := repo.ClaimPasswordReset(ctx, newer, "hash-new"); err != nil || !claimed {
		t.Errorf("the newest link must claim (claimed=%v err=%v)", claimed, err)
	}
}
