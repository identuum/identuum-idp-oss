//go:build integration

// organization_sa_expiry_default_pgx_test.go — OSS-SA-EXPIRY-2 (owner ruling
// f): migration 0051 makes organizations.service_account_expiry_days default
// to 0 and changes no row. The test runs 0051's own Up statements against real
// Postgres inside a transaction that it rolls back: with the old default (365)
// in place a row is inserted without the column, then the migration runs, the
// old row still reads 365, and a new row inserted without the column reads 0.
//
// Requires IDENTUUM_IDP_TEST_DATABASE_URL (see oss_e2e_test.go).

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/migrations"
)

func TestMigration0051_DefaultZeroAndExistingRowsKept(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx := context.Background()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: %v", classifyOpenError(err))
	}
	defer pool.Close()

	data, err := migrations.EmbedFS.ReadFile("0051_service_account_expiry_default_zero.sql")
	if err != nil {
		t.Fatalf("read 0051: %v", err)
	}
	up, _, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatal("0051 has no Down section")
	}
	_, up, _ = strings.Cut(up, "-- +goose Up")

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	insert := func(label string) uuid.UUID {
		t.Helper()
		id, _ := uuid.NewV7()
		sfx := id.String()[:8]
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (id, name, domain, org_slug, active) VALUES ($1, $2, $3, $4, true)`,
			id, "sa-default-"+label+"-"+sfx, "sa-default-"+label+"-"+sfx+".example.invalid", "sa-default-"+label+"-"+sfx); err != nil {
			t.Fatalf("insert %s organization without the column: %v", label, err)
		}
		return id
	}
	days := func(id uuid.UUID) int {
		t.Helper()
		var n int
		if err := tx.QueryRow(ctx, `SELECT service_account_expiry_days FROM organizations WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("read service_account_expiry_days: %v", err)
		}
		return n
	}

	// The state before 0051: the column default as migration 0001 declared it.
	if _, err := tx.Exec(ctx, `ALTER TABLE organizations ALTER COLUMN service_account_expiry_days SET DEFAULT 365`); err != nil {
		t.Fatalf("restore the old default: %v", err)
	}
	existing := insert("existing")
	if got := days(existing); got != 365 {
		t.Fatalf("an organization inserted under the old default reads %d, want 365", got)
	}

	if _, err := tx.Exec(ctx, up); err != nil {
		t.Fatalf("run 0051 Up: %v", err)
	}

	if got := days(existing); got != 365 {
		t.Fatalf("0051 changed an existing organization: %d, want 365 kept", got)
	}
	if got := days(insert("new")); got != 0 {
		t.Fatalf("an organization inserted without the column after 0051 reads %d, want 0", got)
	}
}
