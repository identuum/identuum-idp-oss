//go:build integration

package setup

// SETUP-FIRST-KEY-1: the key provisioning of two setup completion attempts that
// run together must leave exactly one active default signing key. Both read
// the key store before either writes; the second must reuse the key the first
// created and still succeed. The key store is real PostgreSQL in its own
// scratch database, next to the test database, because the lock lives there;
// the setup state, organization and user stores are the package's in-memory
// fakes. The single-winner contract of full completions on PostgreSQL is
// internal/e2e/setup_completion_race_pgx_test.go. FAIL, DO NOT SKIP: the file
// is behind `//go:build integration`.

import (
	"context"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

const firstKeyTestHexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// firstKeyScratchPool creates an empty, migrated database next to the test
// database, drops it when the test ends, and returns a key repository on it.
func firstKeyScratchPool(t *testing.T, name string) (*pgxpool.Pool, *postgres.PgxKeyRepository) {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL is not set; the setup first-key teeth were requested via -tags integration and require a live Postgres DSN")
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
	cipher, err := crypto.NewCryptoService(firstKeyTestHexKey)
	if err != nil {
		t.Fatal("test cipher")
	}
	return pool, postgres.NewPgxKeyRepository(pool, cipher)
}

// firstKeyCounts answers how many signing keys the store holds per algorithm and state.
func firstKeyCounts(t *testing.T, pool *pgxpool.Pool) map[string]int {
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

// readHoldRepo reports each completion's first existing-key read on arrived
// and holds it there until release is closed, so the test decides the order.
type readHoldRepo struct {
	*postgres.PgxKeyRepository
	once    *sync.Once
	arrived chan<- struct{}
	release <-chan struct{}
}

func (r readHoldRepo) GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	keys, err := r.PgxKeyRepository.GetActiveSigningKeys(ctx)
	r.once.Do(func() {
		r.arrived <- struct{}{}
		<-r.release
	})
	return keys, err
}

// waitForLockWaiters returns once want sessions of this database wait for a
// lock, and fails the test if that has not happened within 30 seconds.
func waitForLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got := 0
	for ctx.Err() == nil {
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_locks
			WHERE NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		`).Scan(&got)
		if err == nil && got >= want {
			return
		}
	}
	t.Fatalf("want %d sessions waiting for a lock; saw %d", want, got)
}

// RULE: SETUP-FIRST-KEY-1
//
// The setup completion lock lets only one full completion reach key
// provisioning, so this test drives the provisioning step of two completion
// attempts directly: it must stay serialized by the signing-key provisioning
// lock on its own. A full completion then reuses that key, and a competing
// completion is refused.
func TestSetupComplete_ConcurrentKeyProvisioningCreatesOneDefaultKey(t *testing.T) {
	pool, repo := firstKeyScratchPool(t, "setup_first_key_race_test")
	ctx := context.Background()

	h := newHarness(t)
	banner, err := h.svc.Initialize(ctx, h.dataDir)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	in := validCompleteInput(banner.SetupToken)

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	provision := func() <-chan error {
		deps := h.svc.deps
		deps.KeyService = service.NewKeyService(readHoldRepo{
			PgxKeyRepository: repo, once: &sync.Once{}, arrived: arrived, release: release,
		})
		svc := New(deps)
		done := make(chan error, 1)
		go func() { done <- svc.ensureFirstSigningKey(ctx) }()
		return done
	}

	// A SHARE lock on signing_keys lets every read through and holds every
	// insert, so neither attempt can write before both have decided.
	hold, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin the holding transaction: %v", err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	if _, err := hold.Exec(ctx, `LOCK TABLE signing_keys IN SHARE MODE`); err != nil {
		t.Fatalf("hold inserts into signing_keys: %v", err)
	}

	// Both attempts read the same empty key store, then are released together.
	first := provision()
	second := provision()
	<-arrived
	<-arrived
	close(release)

	// Both attempts now wait in the database: with the provisioning lock,
	// one waits to insert and the other waits for the lock; without it, both
	// have re-read an empty store and wait to insert. Only then are inserts let through.
	waitForLockWaiters(t, pool, 2)
	if err := hold.Rollback(ctx); err != nil {
		t.Fatalf("release the holding transaction: %v", err)
	}

	if err := <-first; err != nil {
		t.Fatalf("the first key provisioning failed: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("the second key provisioning failed although the first succeeded: %v", err)
	}
	counts := firstKeyCounts(t, pool)
	if counts["EdDSA/active"] != 1 || len(counts) != 1 {
		t.Fatalf("two provisioning attempts that both read an empty key store must leave exactly one active EdDSA key; got %v", counts)
	}

	// A full completion reuses the existing default key; a competing
	// completion is refused and writes no key.
	deps := h.svc.deps
	deps.KeyService = service.NewKeyService(repo)
	svc := New(deps)
	if _, err := svc.Complete(ctx, h.dataDir, in); err != nil {
		t.Fatalf("setup completion after provisioning failed: %v", err)
	}
	if _, err := svc.Complete(ctx, h.dataDir, in); !errors.Is(err, ErrAlreadyComplete) {
		t.Fatalf("a second completion must be refused with ErrAlreadyComplete; got %v", err)
	}
	if counts := firstKeyCounts(t, pool); counts["EdDSA/active"] != 1 || len(counts) != 1 {
		t.Fatalf("setup completion must reuse the existing default key; got %v", counts)
	}
}
