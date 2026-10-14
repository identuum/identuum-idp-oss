//go:build integration

package main

// BOOTSTRAP-FIRST-KEY-1: the bootstrap command and a setup completion that run
// together against one empty database must leave exactly one active default
// signing key; both succeed, and the one that did not create the key reuses
// the other's. Every store is real PostgreSQL in its own scratch database next
// to the test database. FAIL, DO NOT SKIP: the file is behind
// `//go:build integration`.

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/internal/setup"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

const bootstrapKeyTestHexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// bootstrapKeyScratchPool creates an empty, migrated database next to the test
// database and drops it when the test ends.
func bootstrapKeyScratchPool(t *testing.T, name string) (*pgxpool.Pool, *crypto.CryptoService) {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL is not set; the bootstrap first-key teeth were requested via -tags integration and require a live Postgres DSN")
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
	cipher, err := crypto.NewCryptoService(bootstrapKeyTestHexKey)
	if err != nil {
		t.Fatal("test cipher")
	}
	return pool, cipher
}

// keyReadHold reports a run's first existing-key read on arrived and holds it
// there until release is closed, so the test decides the order.
type keyReadHold struct {
	*postgres.PgxKeyRepository
	once    *sync.Once
	arrived chan<- struct{}
	release <-chan struct{}
}

func (r keyReadHold) GetActiveSigningKeys(ctx context.Context) ([]domain.SigningKey, error) {
	keys, err := r.PgxKeyRepository.GetActiveSigningKeys(ctx)
	r.once.Do(func() {
		r.arrived <- struct{}{}
		<-r.release
	})
	return keys, err
}

// RULE: BOOTSTRAP-FIRST-KEY-1
func TestBootstrap_ConcurrentWithSetupCompletionCreatesOneDefaultKey(t *testing.T) {
	pool, cipher := bootstrapKeyScratchPool(t, "bootstrap_setup_key_race_test")
	ctx := context.Background()
	repos := postgres.NewPgxRepositories(pool, cipher)
	keyRepo := postgres.NewPgxKeyRepository(pool, cipher)

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	hold := func() keyReadHold {
		return keyReadHold{PgxKeyRepository: keyRepo, once: &sync.Once{}, arrived: arrived, release: release}
	}

	dataDir := t.TempDir()
	setupSvc := setup.New(setup.Deps{
		Repo:       postgres.NewPgxSetupStateRepository(pool),
		OrgService: service.NewOrganizationService(nil, repos.Organization),
		KeyService: service.NewKeyService(hold()),
		OrgRepo:    repos.Organization,
		UserRepo:   repos.User,
		Issuer:     "http://localhost:7113",
	})
	banner, err := setupSvc.Initialize(ctx, dataDir)
	if err != nil || banner == nil {
		t.Fatalf("Initialize: banner=%v err=%v", banner != nil, err)
	}

	// A SHARE lock on signing_keys lets every read through and holds every
	// insert, so neither run can write before both have decided.
	tableHold, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin the holding transaction: %v", err)
	}
	defer func() { _ = tableHold.Rollback(ctx) }()
	if _, err := tableHold.Exec(ctx, `LOCK TABLE signing_keys IN SHARE MODE`); err != nil {
		t.Fatalf("hold inserts into signing_keys: %v", err)
	}

	// The setup completion creates the organization and the site_admin, then
	// reads an empty key store and waits. Bootstrap starts only then and reads
	// the same empty key store. Both are released together.
	setupDone := make(chan error, 1)
	go func() {
		_, err := setupSvc.Complete(ctx, dataDir, setup.CompleteInput{
			SetupToken:         banner.SetupToken,
			OrganizationName:   "Acme Corp",
			OrganizationDomain: "acme.example",
			AdminEmail:         "owner@acme.example",
			AdminPassword:      "Very-Long-Test-Password-1!",
		})
		setupDone <- err
	}()
	<-arrived
	var stdout, stderr bytes.Buffer
	bootstrapDone := make(chan int, 1)
	go func() {
		bootstrapDone <- bootstrapCore(ctx, bootstrapDeps{Keys: hold(), Users: repos.User}, bootstrapOptions{
			Email:     domain.SiteAdminEmail,
			Password:  "Demo-Only-Not-Printed-Anywhere-1!",
			Algorithm: domain.KeyAlgorithmEdDSA,
		}, &stdout, &stderr)
	}()
	<-arrived
	close(release)

	// Both runs now wait in the database: with the provisioning lock, one
	// waits to insert and the other waits for the lock; without it, both
	// wait to insert. Only then are inserts let through.
	waitForKeyLockWaiters(t, pool, 2)
	if err := tableHold.Rollback(ctx); err != nil {
		t.Fatalf("release the holding transaction: %v", err)
	}

	if err := <-setupDone; err != nil {
		t.Fatalf("the setup completion failed: %v", err)
	}
	if rc := <-bootstrapDone; rc != 0 {
		t.Fatalf("bootstrap failed: rc=%d stderr=%q", rc, stderr.String())
	}
	var counts = map[string]int{}
	rows, err := pool.Query(ctx, `SELECT algorithm || '/' || state, count(*) FROM signing_keys GROUP BY 1`)
	if err != nil {
		t.Fatalf("count signing keys: %v", err)
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatalf("scan count: %v", err)
		}
		counts[k] = n
	}
	rows.Close()
	if counts["EdDSA/active"] != 1 || len(counts) != 1 {
		t.Fatalf("bootstrap and a setup completion that both read an empty key store must leave exactly one active EdDSA key; got %v", counts)
	}
	if out := stdout.String(); !strings.Contains(out, "signing key already present") && !strings.Contains(out, "created signing key") {
		t.Fatalf("bootstrap must report the key it created or found; got %q", out)
	}
}

// waitForKeyLockWaiters returns once want sessions of this database wait for a
// lock, and fails the test if that has not happened within 30 seconds.
func waitForKeyLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
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
