//go:build integration

package postgres_test

// G2 store: users.admin_password_set_at (migration 0055, proposed) is NULL for
// rows written before it; UpdateUserOptions.AdminPasswordSetAt writes it in
// the same UPDATE as the hash and the flag (pointer to the zero time = NULL);
// a completed reset (ClaimPasswordReset) clears it with the flag.
// RED AT VET at 495885c (AdminPasswordSetAt undefined). Needs PostgreSQL.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

func TestAdminPasswordSetAt_WrittenAndClearedWithTheFlag(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	orgID, userID := uuid.New(), uuid.New()
	slug := "g2-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
		orgID, "G2 "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// A row written the old way: no time.
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, organization_id, role, email_verified, requires_password_change) VALUES ($1, $2, 'x', $3, 'org_user', true, true)`,
		userID, "u-"+slug+"@example.test", orgID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM password_resets WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	readSetAt := func() *time.Time {
		var v *time.Time
		if err := pool.QueryRow(ctx, `SELECT admin_password_set_at FROM users WHERE id = $1`, userID).Scan(&v); err != nil {
			t.Fatalf("read admin_password_set_at: %v", err)
		}
		return v
	}
	if v := readSetAt(); v != nil {
		t.Fatalf("a row written without the column has admin_password_set_at = %v; want NULL", v)
	}

	users := postgres.NewPgxUserRepository(pool)
	hash, flag, at := "hash-admin-set", true, time.Now().UTC().Truncate(time.Microsecond)
	got, err := users.Update(ctx, userID, orgID, repository.UpdateUserOptions{Password: &hash, RequiresPasswordChange: &flag, AdminPasswordSetAt: &at})
	if err != nil || got == nil {
		t.Fatalf("Update = %v %v", got, err)
	}
	if got.AdminPasswordSetAt == nil || !got.AdminPasswordSetAt.Equal(at) {
		t.Errorf("RETURNING AdminPasswordSetAt = %v; want the written time", got.AdminPasswordSetAt)
	}
	if v := readSetAt(); v == nil || !v.Equal(at) {
		t.Errorf("stored admin_password_set_at = %v; want the written time", v)
	}
	if u, err := users.GetByIDWithOrg(ctx, userID); err != nil || u.AdminPasswordSetAt == nil {
		t.Errorf("GetByIDWithOrg does not read admin_password_set_at (%v)", err)
	}

	// A completed reset clears the flag and the time in its transaction.
	tok := "g2-" + uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES ($1, $2, NOW() + interval '1 hour', NOW())`, userID, tok); err != nil {
		t.Fatalf("seed reset: %v", err)
	}
	if _, claimed, err := postgres.NewPgxPasswordResetRepository(pool).ClaimPasswordReset(ctx, tok, "hash-chosen"); err != nil || !claimed {
		t.Fatalf("claim = %v %v; want claimed", claimed, err)
	}
	if v := readSetAt(); v != nil {
		t.Errorf("admin_password_set_at = %v after a completed reset; want NULL", v)
	}

	// Pointer to the zero time writes NULL (a lasting password).
	if _, err := users.Update(ctx, userID, orgID, repository.UpdateUserOptions{AdminPasswordSetAt: &at}); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	zero := time.Time{}
	off := false
	if _, err := users.Update(ctx, userID, orgID, repository.UpdateUserOptions{Password: &hash, RequiresPasswordChange: &off, AdminPasswordSetAt: &zero}); err != nil {
		t.Fatalf("lasting password: %v", err)
	}
	if v := readSetAt(); v != nil {
		t.Errorf("admin_password_set_at = %v after a lasting password; want NULL", v)
	}
}
