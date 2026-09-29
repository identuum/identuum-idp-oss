//go:build integration

package postgres_test

// OSS-RC: CountRecoveryBlockingOrgAdminsByOrganizations counts the org_admins
// that block site_admin recovery delegation in the site-admin admin state: a
// verified admin, or a pending one whose activation has not expired. An
// expired pending admin does not block. Against the live DB; FAIL-not-skip.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func TestCountRecoveryBlockingOrgAdmins_ValidPendingBlocksExpiredDoesNot(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()

	seed := func(kind string) uuid.UUID {
		orgID := uuid.New()
		slug := "rb-" + uuid.NewString()[:8]
		if _, err := pool.Exec(ctx,
			`INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, false)`,
			orgID, "RB "+slug, slug+".example.test", slug); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		q := map[string]string{
			"valid":    `NOW() + interval '1 hour', false`,
			"expired":  `NOW() - interval '1 hour', false`,
			"verified": `NULL, true`,
		}[kind]
		if _, err := pool.Exec(ctx, `
			INSERT INTO users (id, email, password_hash, organization_id, role, activation_token_hash, activation_token_expires_at, email_verified)
			VALUES ($1, $2, 'x', $3, 'org_admin', 'h-'||$1::text, `+q+`)`,
			uuid.New(), "admin-"+slug+"@example.test", orgID); err != nil {
			t.Fatalf("seed %s admin: %v", kind, err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE organization_id = $1`, orgID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
		})
		return orgID
	}
	valid, expired, verified := seed("valid"), seed("expired"), seed("verified")

	got, err := postgres.NewPgxUserRepository(pool).CountRecoveryBlockingOrgAdminsByOrganizations(ctx, []uuid.UUID{valid, expired, verified})
	if err != nil {
		t.Fatal(err)
	}
	if got[valid] != 1 || got[expired] != 0 || got[verified] != 1 {
		t.Fatalf("blocking counts valid/expired/verified = %d/%d/%d, want 1/0/1", got[valid], got[expired], got[verified])
	}
}
