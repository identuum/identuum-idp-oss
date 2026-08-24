//go:build integration

package postgres_test

// Integration teeth for organization activation single-use (ACTIVATION-CONSUME-ONCE-1).
//
// Driven against the LIVE DB through the real OrganizationActivationService
// over the real pgx user + organization repositories: ValidateActivationToken
// is read-only (a consume right after a validate still succeeds), and
// ConsumeActivationToken is single-use + atomic (it claims the token and flips
// the org active in one transaction; a second consume of the same token claims
// nothing). FAIL-not-skip.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

type activationNoopNotifier struct{}

func (activationNoopNotifier) SendActivationEmail(context.Context, *domain.User, string, time.Time) error {
	return nil
}

func seedInactiveOrgWithActivationUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenHash string) uuid.UUID {
	t.Helper()
	orgID := uuid.New()
	slug := "act-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, false)`,
		orgID, "Act "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, organization_id, role, activation_token_hash, activation_token_expires_at)
		VALUES ($1, $2, 'x', $3, 'org_admin', $4, NOW() + interval '1 hour')`,
		uuid.New(), "admin-"+slug+"@example.test", orgID, tokenHash); err != nil {
		t.Fatalf("seed activation user: %v", err)
	}
	return orgID
}

// RULE: ACTIVATION-CONSUME-ONCE-1
func TestOrganizationActivation_ConsumableExactlyOnce(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()

	userRepo := postgres.NewPgxUserRepository(pool)
	orgRepo := postgres.NewPgxOrganizationRepository(pool)
	svc := service.NewOrganizationActivationService(service.OrganizationActivationServiceConfig{
		Users:     userRepo,
		Orgs:      orgRepo,
		OrgsAdmin: orgRepo,
		Notifier:  activationNoopNotifier{},
	})

	rawToken := "activation-" + uuid.NewString()
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(sum[:])
	orgID := seedInactiveOrgWithActivationUser(t, ctx, pool, tokenHash)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE organization_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	// Validate is read-only: it reports the pending activation without consuming.
	res, err := svc.ValidateActivationToken(ctx, rawToken)
	if err != nil {
		t.Fatalf("PREMISE FAILED: ValidateActivationToken on a live token: %v", err)
	}
	if res == nil || res.OrgID != orgID {
		t.Fatalf("ValidateActivationToken must resolve the pending org, got %+v", res)
	}

	// Consume right after validate SUCCEEDS (proves validate did not consume)
	// and atomically flips the org active.
	pw := "SuperSecret123!xyz"
	_, org, err := svc.ConsumeActivationToken(ctx, service.ConsumeActivationInput{Token: rawToken, Password: pw})
	if err != nil {
		t.Fatalf("consume after validate must succeed (validate must be read-only): %v", err)
	}
	if org == nil || !org.Active {
		t.Fatalf("a successful consume must flip the org active, got %+v", org)
	}
	// Atomic claim: the activation_token_hash is nulled in the SAME transaction
	// that activated the org, so the token is spent and can never be replayed.
	var hashAfter *string
	if err := pool.QueryRow(ctx, `SELECT activation_token_hash FROM users WHERE organization_id = $1`, orgID).Scan(&hashAfter); err != nil {
		t.Fatalf("read activation_token_hash after consume: %v", err)
	}
	if hashAfter != nil {
		t.Errorf("consume must claim the token: activation_token_hash must be NULL after consume, got %q", *hashAfter)
	}

	// Single-use: a second consume of the same token claims nothing.
	if _, _, err := svc.ConsumeActivationToken(ctx, service.ConsumeActivationInput{Token: rawToken, Password: pw}); err == nil {
		t.Errorf("a replayed activation token must NOT consume twice")
	}
	// The burned token no longer validates.
	if _, err := svc.ValidateActivationToken(ctx, rawToken); err == nil {
		t.Errorf("a consumed activation token must no longer validate")
	}
}
