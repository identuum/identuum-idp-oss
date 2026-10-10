//go:build integration

package runtime

// SIGNING-KEY-PROVISION-1 (review OSS-RS256-REVIEW F1): startup provisioning
// with IDENTUUM_IDP_ADVERTISE_RS256 on runs before the single-replica lease
// decides which process serves, and the lease can be switched off. Two
// processes starting together against one database must still leave exactly
// one active RSA key and one active default key. Each scenario gets its own
// scratch database next to the test database, because the decision reads every
// signing key in the store. FAIL, DO NOT SKIP: the file is behind
// `//go:build integration`.

import (
	"context"
	"io"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

const provisionTestHexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// provisionScratchPool creates an empty, migrated database next to the test
// database, drops it when the test ends, and returns a key repository on it.
func provisionScratchPool(t *testing.T, name string) (*pgxpool.Pool, *postgres.PgxKeyRepository) {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL is not set; the provisioning teeth were requested via -tags integration and require a live Postgres DSN")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatal("open the test database (URL redacted)")
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
			t.Errorf("drop the scratch database %s: %v", name, err)
		}
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("the test DSN is not a URL")
	}
	u.Path = "/" + name
	db, err := postgres.OpenStdlibDB(u.String())
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := postgres.RunMigrations(ctx, db); err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}
	_ = db.Close()
	pool, err := postgres.NewPool(ctx, u.String(), nil)
	if err != nil {
		t.Fatalf("pool on %s: %v", name, err)
	}
	t.Cleanup(pool.Close)
	cipher, err := crypto.NewCryptoService(provisionTestHexKey)
	if err != nil {
		t.Fatal("test cipher")
	}
	return pool, postgres.NewPgxKeyRepository(pool, cipher)
}

// keyCounts answers how many signing keys the store holds per algorithm and state.
func keyCounts(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT algorithm || '/' || state, count(*) FROM signing_keys GROUP BY 1`)
	if err != nil {
		t.Fatalf("count signing keys: %v", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatalf("scan count: %v", err)
		}
		counts[k] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return counts
}

// readRendezvousRepo holds a provisioning run after its existing-key read until
// the other run has read too, so both observe the same store before either writes.
type readRendezvousRepo struct {
	*postgres.PgxKeyRepository
	once *sync.Once
	both *sync.WaitGroup
}

func (r readRendezvousRepo) GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	keys, err := r.PgxKeyRepository.GetActiveSigningKeys(ctx)
	r.once.Do(func() {
		r.both.Done()
		r.both.Wait()
	})
	return keys, err
}

// RULE: SIGNING-KEY-PROVISION-1
func TestSigningKeyProvision(t *testing.T) {
	t.Run("concurrent starts create one active key per algorithm", provisionConcurrentStarts)
	t.Run("start, reuse, rotation and option-off control", provisionLifecycle)
}

func provisionConcurrentStarts(t *testing.T) {
	pool, repo := provisionScratchPool(t, "rs256_provision_race_test")
	ctx := context.Background()
	var both sync.WaitGroup
	both.Add(2)
	errs := make(chan error, 2)
	for range 2 {
		run := readRendezvousRepo{PgxKeyRepository: repo, once: &sync.Once{}, both: &both}
		go func() {
			errs <- ensureAdvertisedRS256Key(ctx, service.NewKeyService(run), true, io.Discard)
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("a concurrent provisioning run failed: %v", err)
		}
	}
	counts := keyCounts(t, pool)
	if counts["RS256/active"] != 1 || counts["EdDSA/active"] != 1 || len(counts) != 2 {
		t.Fatalf("two concurrent starts on an empty store must leave exactly one active RS256 and one active EdDSA key; got %v", counts)
	}
}

func provisionLifecycle(t *testing.T) {
	pool, repo := provisionScratchPool(t, "rs256_provision_life_test")
	ctx := context.Background()
	keys := service.NewKeyService(repo)
	start := func(enabled bool) {
		t.Helper()
		if err := ensureAdvertisedRS256Key(ctx, keys, enabled, io.Discard); err != nil {
			t.Fatalf("provisioning (enabled=%v) failed: %v", enabled, err)
		}
	}
	activeRSA := func() string {
		t.Helper()
		var kid string
		if err := pool.QueryRow(ctx, `SELECT kid FROM signing_keys WHERE algorithm = 'RS256' AND state = 'active'`).Scan(&kid); err != nil {
			t.Fatalf("read the one active RS256 key: %v", err)
		}
		return kid
	}

	// Control: the option off reads and writes nothing.
	start(false)
	if counts := keyCounts(t, pool); len(counts) != 0 {
		t.Fatalf("option off must create no signing key; got %v", counts)
	}

	// A single start on an empty store creates one default and one RSA key.
	start(true)
	if counts := keyCounts(t, pool); counts["EdDSA/active"] != 1 || counts["RS256/active"] != 1 || len(counts) != 2 {
		t.Fatalf("single start: want one active EdDSA and one active RS256; got %v", counts)
	}
	first := activeRSA()

	// A restart reuses both.
	start(true)
	if counts := keyCounts(t, pool); counts["EdDSA/active"] != 1 || counts["RS256/active"] != 1 || len(counts) != 2 {
		t.Fatalf("restart must reuse the keys; got %v", counts)
	}
	if activeRSA() != first {
		t.Fatal("restart replaced the active RSA key")
	}

	// A normal rotation: the replacement is reused on restart and the old key
	// stays the one grace-period key.
	next, err := keys.Generate(ctx, service.GenerateKeyOptions{Algorithm: "RS256", State: domain.KeyStateRotating})
	if err != nil {
		t.Fatalf("generate the replacement: %v", err)
	}
	if err := keys.Rotate(ctx, first, next.KID, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	start(true)
	if counts := keyCounts(t, pool); counts["RS256/active"] != 1 || counts["RS256/rotating"] != 1 || counts["EdDSA/active"] != 1 || len(counts) != 3 {
		t.Fatalf("after rotation a restart must reuse the replacement; got %v", counts)
	}
	if activeRSA() != next.KID {
		t.Fatal("restart after rotation did not keep the replacement as the active RSA key")
	}

	// Rotating-only RSA does not satisfy the promise: a new active key is made.
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET state = 'rotating' WHERE algorithm = 'RS256' AND state = 'active'`); err != nil {
		t.Fatalf("retire the active RSA key: %v", err)
	}
	start(true)
	if counts := keyCounts(t, pool); counts["RS256/active"] != 1 || counts["RS256/rotating"] != 2 || counts["EdDSA/active"] != 1 || len(counts) != 3 {
		t.Fatalf("rotating-only RSA must get one new active key; got %v", counts)
	}
}
