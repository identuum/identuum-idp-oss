//go:build integration

package postgres_test

// The organization-activation claim redeems only an activation token: the
// token of a not-yet-activated, unbanned org_admin of an inactive
// organization. A user-invite token (an org_user) or the token of an admin
// who already activated claims nothing and leaves the organization as it was.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

func seedActivationClaimCase(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role string, verified bool) (uuid.UUID, string) {
	t.Helper()
	orgID := uuid.New()
	slug := "acp-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, false)`,
		orgID, "Acp "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	raw := "claim-" + uuid.NewString()
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, organization_id, role, email_verified, activation_token_hash, activation_token_expires_at)
		VALUES ($1, $2, 'x', $3, $4, $5, $6, NOW() + interval '1 hour')`,
		uuid.New(), "u-"+slug+"@example.test", orgID, role, verified, hash); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE organization_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})
	return orgID, hash
}

func TestConsumeActivationToken_OnlyAPendingOrgAdmin(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := postgres.NewPgxUserRepository(pool)

	for name, tc := range map[string]struct {
		role     string
		verified bool
	}{
		"org_user token":          {"org_user", false},
		"already-activated admin": {"org_admin", true},
	} {
		orgID, hash := seedActivationClaimCase(t, ctx, pool, tc.role, tc.verified)
		_, claimed, err := repo.ConsumeActivationToken(ctx, hash, "new-hash")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if claimed {
			t.Errorf("%s: the activation claim must refuse this token", name)
		}
		var active bool
		if err := pool.QueryRow(ctx, `SELECT active FROM organizations WHERE id = $1`, orgID).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if active {
			t.Errorf("%s: the organization must stay inactive", name)
		}
	}

	// The legitimate case still works.
	orgID, hash := seedActivationClaimCase(t, ctx, pool, "org_admin", false)
	if _, claimed, err := repo.ConsumeActivationToken(ctx, hash, "new-hash"); err != nil || !claimed {
		t.Fatalf("a pending org_admin's activation must claim, got claimed=%v err=%v", claimed, err)
	}
	var active bool
	if err := pool.QueryRow(ctx, `SELECT active FROM organizations WHERE id = $1`, orgID).Scan(&active); err != nil || !active {
		t.Fatalf("a claimed activation must activate the organization, active=%v err=%v", active, err)
	}
}
