//go:build integration

package postgres_test

// Integration teeth for the claim consume (OSS-SEC).
//
// Driven against the LIVE DB through the real ClaimService over the real pgx
// claim, organization and user repositories. One claim link yields at most
// one user, and the burn, the user and the attempt count commit or roll back
// together: a user creation that fails after the burn leaves the link usable.
// FAIL-not-skip.

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const claimAtomicPassword = "Claim-Fixture-42abcX!"

func claimAtomicService(pool *pgxpool.Pool) *service.ClaimService {
	orgs := postgres.NewPgxOrganizationRepository(pool)
	users := postgres.NewPgxUserRepository(pool)
	return service.NewClaimService(service.ClaimServiceConfig{
		Claims:    postgres.NewPgClaimRepository(pool),
		Orgs:      orgs,
		OrgsAdmin: orgs,
		Users:     users,
		Exists:    users,
	})
}

func seedClaimOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	orgID := uuid.New()
	slug := "claim-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, false)`,
		orgID, "Claim "+slug, slug+".example.test", slug); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return orgID
}

func countOrgUsers(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (users, admins int) {
	t.Helper()
	if err := pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE role = 'org_admin') FROM users WHERE organization_id = $1`,
		orgID).Scan(&users, &admins); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return users, admins
}

// OSS-SEC: N concurrent consumes of one valid link: exactly one success, one user,
// one org_admin; every other request gets the plain failure.
func TestClaimConsume_ConcurrentConsumesYieldOneUser(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := claimAtomicService(pool)
	orgID := seedClaimOrg(t, ctx, pool)
	email := "race-" + uuid.NewString()[:8] + "@example.test"
	raw, _, err := svc.GenerateClaimToken(ctx, orgID, email)
	if err != nil {
		t.Fatalf("generate claim: %v", err)
	}
	const n = 8
	results := make([]*service.ConsumeClaimResult, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res, cErr := svc.ConsumeClaim(ctx, service.ConsumeClaimInput{Token: raw, Email: email, Password: claimAtomicPassword})
			if cErr != nil {
				t.Errorf("consume %d: %v", i, cErr)
			}
			results[i] = res
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, r := range results {
		if r == nil {
			continue
		}
		if r.Success {
			wins++
		} else if r.AttemptsExhausted || r.AttemptsRemaining != 0 {
			t.Errorf("a losing consume answered %+v; want the plain {success:false}", *r)
		}
	}
	users, admins := countOrgUsers(t, ctx, pool, orgID)
	if wins != 1 || users != 1 || admins != 1 {
		t.Fatalf("%d concurrent consumes: %d successes, %d users, %d org_admins; want exactly 1 of each", n, wins, users, admins)
	}
}

// OSS-SEC: a user creation that fails after the burn rolls the burn back: the link
// stays usable, no user exists, and the next consume succeeds.
func TestClaimConsume_FailedUserCreateLeavesTheLinkUsable(t *testing.T) {
	pool := keyEncPool(t)
	defer pool.Close()
	ctx := context.Background()
	svc := claimAtomicService(pool)
	orgID := seedClaimOrg(t, ctx, pool)
	email := "boom-" + uuid.NewString()[:8] + "@example.test"
	raw, _, err := svc.GenerateClaimToken(ctx, orgID, email)
	if err != nil {
		t.Fatalf("generate claim: %v", err)
	}
	// Force the user INSERT to fail for this one address, after every check
	// and after the burn.
	fn := "claim_atomic_boom_" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx, `CREATE FUNCTION `+fn+`() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.email = '`+email+`' THEN RAISE EXCEPTION 'forced user-create failure'; END IF;
  RETURN NEW;
END $$`); err != nil {
		t.Fatalf("create trigger function: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER `+fn+` BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	dropped := false
	drop := func() {
		if dropped {
			return
		}
		dropped = true
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+fn+` ON users`)
		_, _ = pool.Exec(ctx, `DROP FUNCTION IF EXISTS `+fn+`()`)
	}
	defer drop()

	res, err := svc.ConsumeClaim(ctx, service.ConsumeClaimInput{Token: raw, Email: email, Password: claimAtomicPassword})
	if err != nil || res == nil || res.Success {
		t.Fatalf("consume with a failing user create = %+v, %v; want {success:false}", res, err)
	}
	if users, _ := countOrgUsers(t, ctx, pool, orgID); users != 0 {
		t.Fatalf("a failed consume left %d user(s)", users)
	}
	var claims, attempts int
	if err := pool.QueryRow(ctx, `SELECT count(*), COALESCE(max(attempt_count), 0) FROM organization_claims WHERE organization_id = $1`, orgID).Scan(&claims, &attempts); err != nil {
		t.Fatalf("read claim: %v", err)
	}
	if claims != 1 || attempts != 0 {
		t.Fatalf("after a failed user create: %d claim row(s), attempt_count %d; want the link intact (1 row, 0 attempts)", claims, attempts)
	}
	drop()
	res, err = svc.ConsumeClaim(ctx, service.ConsumeClaimInput{Token: raw, Email: email, Password: claimAtomicPassword})
	if err != nil || res == nil || !res.Success {
		t.Fatalf("the retried consume = %+v, %v; want success", res, err)
	}
	if users, admins := countOrgUsers(t, ctx, pool, orgID); users != 1 || admins != 1 {
		t.Fatalf("after the retry: %d users, %d org_admins; want 1 and 1", users, admins)
	}
}
