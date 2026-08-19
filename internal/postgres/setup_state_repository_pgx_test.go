//go:build integration

// Integration tests for PgxSetupStateRepository.
//
// Prerequisites:
//   - Set IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) to
//     a Postgres connection string. The test applies OSS migrations
//     automatically and resets the singleton row before each subtest.
//   - All tests skip cleanly when neither env var is set.
//
// Safety:
//   - No DB URLs, token values, or hashes are echoed in test failure
//     messages.
package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

func setupStateTestDBURL(t *testing.T) string {
	t.Helper()
	for _, env := range []string{"IDENTUUM_IDP_TEST_DATABASE_URL", "IDENTUUM_IDP_DATABASE_URL"} {
		if v := os.Getenv(env); v != "" {
			if err := testsupport.RequireTestDatabase(v); err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	// FAIL, DO NOT SKIP (CE-DB-PROVISION, 2026-08-02). Behind
	// `//go:build integration`, so the caller asked for these by name. Same rule
	// as testDBURL/P2-20 — a skip made the setup-state repository look covered.
	t.Fatal("IDENTUUM_IDP_TEST_DATABASE_URL (or IDENTUUM_IDP_DATABASE_URL) is not set; " +
		"the setup-state integration tests were requested via -tags integration and require " +
		"a live Postgres DSN. `make integration-test` supplies it automatically (Makefile)")
	return ""
}

// resetSetupStateRow truncates the singleton row back to the
// freshly-migrated shape so each subtest starts at a known state.
func resetSetupStateRow(t *testing.T, ctx context.Context, db postgres.DBTX) {
	t.Helper()
	_, err := db.Exec(ctx,
		`UPDATE system_setup_state
		   SET status = $2,
		       setup_token_hash = NULL,
		       setup_token_created_at = NULL,
		       completed_at = NULL,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = $1`,
		domain.SetupStateSingletonID, domain.SetupStatusRequired,
	)
	if err != nil {
		t.Fatalf("reset setup state row: %v", err)
	}
}

// withIsolatedSetupState runs fn against the setup-state repo inside a single
// transaction that first resets the singleton row.
//
// system_setup_state is a fixed-ID production singleton
// (domain.SetupStateSingletonID) written by production code this test must NOT
// change: SetupService.Initialize on a runtime Start (internal/runtime/runtime.go:389,
// exercised by the DB-backed tests in internal/runtime + pkg/runtime) and e2e's
// TestE2E_OSS_SetupFlow both mutate that one row. Now that
// `make integration-test` runs internal/postgres alongside those packages
// against a SHARED Postgres, the row cannot be partitioned per test.
//
// Isolation without serialising the whole gate: the reset's UPDATE takes a
// row lock that is held for the entire subtest, so any concurrent writer to
// the singleton blocks until fn returns — the subtest therefore sees only its
// own writes — and the deferred Rollback leaves the row exactly as it found it
// (real cleanup, no residue for the next package or the next `-count` run).
func withIsolatedSetupState(t *testing.T, ctx context.Context, pool postgres.DBTX, fn func(repo *postgres.PgxSetupStateRepository)) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin isolation tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	resetSetupStateRow(t, ctx, tx)
	fn(postgres.NewPgxSetupStateRepository(tx))
}

func TestSetupStateRepository_Integration(t *testing.T) {
	dbURL := setupStateTestDBURL(t)

	stdlibDB, err := postgres.OpenStdlibDB(dbURL)
	if err != nil {
		t.Fatalf("open stdlib db (URL redacted): %v", err)
	}
	if _, err := postgres.RunMigrations(context.Background(), stdlibDB); err != nil {
		t.Fatalf("run migrations (URL redacted): %v", err)
	}
	_ = stdlibDB.Close()

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("new pool (URL redacted): %v", err)
	}
	defer pool.Close()

	t.Run("Get returns seeded row", func(t *testing.T) {
		withIsolatedSetupState(t, ctx, pool, func(repo *postgres.PgxSetupStateRepository) {
			state, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if state.ID != domain.SetupStateSingletonID {
				t.Errorf("ID = %v; want sentinel %v", state.ID, domain.SetupStateSingletonID)
			}
			if state.Status != domain.SetupStatusRequired {
				t.Errorf("Status = %q; want %q", state.Status, domain.SetupStatusRequired)
			}
			if state.SetupTokenHash != "" {
				t.Errorf("SetupTokenHash should be empty on fresh row")
			}
			if state.SetupTokenCreatedAt != nil {
				t.Errorf("SetupTokenCreatedAt should be nil on fresh row")
			}
			if state.CompletedAt != nil {
				t.Errorf("CompletedAt should be nil on fresh row")
			}
		})
	})

	t.Run("EnsureRow is idempotent", func(t *testing.T) {
		withIsolatedSetupState(t, ctx, pool, func(repo *postgres.PgxSetupStateRepository) {
			if err := repo.EnsureRow(ctx); err != nil {
				t.Fatalf("EnsureRow first call: %v", err)
			}
			if err := repo.EnsureRow(ctx); err != nil {
				t.Fatalf("EnsureRow second call: %v", err)
			}
			state, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("Get after EnsureRow: %v", err)
			}
			if state.Status != domain.SetupStatusRequired {
				t.Errorf("Status after EnsureRow = %q; want %q", state.Status, domain.SetupStatusRequired)
			}
		})
	})

	t.Run("UpdateTokenHash sets hash + created_at without flipping status", func(t *testing.T) {
		withIsolatedSetupState(t, ctx, pool, func(repo *postgres.PgxSetupStateRepository) {
			const hash = "deadbeef0000000000000000000000000000000000000000000000000000abcd"
			createdAt := time.Now().UTC().Truncate(time.Second)
			if err := repo.UpdateTokenHash(ctx, hash, createdAt); err != nil {
				t.Fatalf("UpdateTokenHash: %v", err)
			}
			state, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("Get after UpdateTokenHash: %v", err)
			}
			if state.SetupTokenHash != hash {
				t.Errorf("SetupTokenHash mismatch")
			}
			if state.SetupTokenCreatedAt == nil || !state.SetupTokenCreatedAt.Equal(createdAt) {
				t.Errorf("SetupTokenCreatedAt = %v; want %v", state.SetupTokenCreatedAt, createdAt)
			}
			if state.Status != domain.SetupStatusRequired {
				t.Errorf("Status flipped unexpectedly: %q", state.Status)
			}
		})
	})

	t.Run("MarkComplete flips status, sets completed_at, clears token hash", func(t *testing.T) {
		withIsolatedSetupState(t, ctx, pool, func(repo *postgres.PgxSetupStateRepository) {
			const hash = "feedface0000000000000000000000000000000000000000000000000000abcd"
			if err := repo.UpdateTokenHash(ctx, hash, time.Now().UTC()); err != nil {
				t.Fatalf("UpdateTokenHash: %v", err)
			}

			completedAt := time.Now().UTC().Truncate(time.Second)
			if err := repo.MarkComplete(ctx, completedAt); err != nil {
				t.Fatalf("MarkComplete: %v", err)
			}

			state, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("Get after MarkComplete: %v", err)
			}
			if state.Status != domain.SetupStatusComplete {
				t.Errorf("Status = %q; want %q", state.Status, domain.SetupStatusComplete)
			}
			if state.SetupTokenHash != "" {
				t.Errorf("SetupTokenHash should be cleared after MarkComplete")
			}
			if state.CompletedAt == nil || !state.CompletedAt.Equal(completedAt) {
				t.Errorf("CompletedAt = %v; want %v", state.CompletedAt, completedAt)
			}
			if !state.IsComplete() {
				t.Errorf("IsComplete() should be true after MarkComplete")
			}
		})
	})

	t.Run("MarkComplete is idempotent", func(t *testing.T) {
		withIsolatedSetupState(t, ctx, pool, func(repo *postgres.PgxSetupStateRepository) {
			now := time.Now().UTC().Truncate(time.Second)
			if err := repo.MarkComplete(ctx, now); err != nil {
				t.Fatalf("first MarkComplete: %v", err)
			}
			if err := repo.MarkComplete(ctx, now.Add(time.Second)); err != nil {
				t.Fatalf("second MarkComplete: %v", err)
			}
			state, err := repo.Get(ctx)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !state.IsComplete() {
				t.Errorf("IsComplete() should remain true after re-mark")
			}
		})
	})
}
